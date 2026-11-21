/* Request signatures, receipts and custody receipts (spec/02, spec/06), and sealed requests (spec/09). */

#include "puddle_proto.h"

#include <chrono>
#include <mutex>
#include <new>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#define NONCE_REMEMBER_MS (2 * PP_SIG_WINDOW_MS)

static int64_t wall_ms(void)
{
    return (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

int pp_reqsig_canonical(char *out, size_t cap, const char *method, const char *target, const void *body, size_t body_len, int64_t ts,
                        const char *nonce, const char *recipient)
{
    char hash[65];
    pp_sha256_hex(body ? body : "", body ? body_len : 0, hash);
    int n = snprintf(out, cap, "puddle-request-v1\n%s\n%s\n%s\n%lld\n%s\n%s", method, target, hash, (long long)ts, nonce, recipient);
    return (n > 0 && (size_t)n < cap) ? n : -1;
}

static int valid_method(const char *m)
{
    size_t n = m ? strlen(m) : 0;
    if (n == 0 || n > 7)
        return 0;
    for (size_t i = 0; i < n; i++)
        if (m[i] < 'A' || m[i] > 'Z')
            return 0;
    return 1;
}

/* a request target as sent: printable, no spaces or line breaks */
static int valid_target(const char *t)
{
    size_t n = t ? strlen(t) : 0;
    if (n == 0 || n > 1100 || t[0] != '/')
        return 0;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)t[i] <= 0x20 || (unsigned char)t[i] >= 0x7f)
            return 0;
    return 1;
}

static int is_hex64(const char *s)
{
    unsigned char raw[32];
    return s && strlen(s) == 64 && pp_hex_decode(s, raw, 32) == 0;
}

static int new_nonce(char nonce[32])
{
    unsigned char raw[16];
    return RAND_bytes(raw, sizeof raw) == 1 && pp_base64_encode(raw, sizeof raw, nonce, 32) ? 0 : -1;
}

int pp_reqsig_sign(const pp_signer *s, const char *method, const char *target, const void *body, size_t body_len,
                   const char *recipient_id, int64_t at_ms, const char *nonce_in, char *out, size_t cap)
{
    char nonce[48];
    if (!s || !s->id || !pp_id_valid(s->id) || !s->sign || !valid_method(method) || !valid_target(target) || !recipient_id ||
        !(pp_id_valid(recipient_id) || !strcmp(recipient_id, PP_RECIPIENT_ANY)))
        return -1;
    if (nonce_in) {
        if (strlen(nonce_in) < 16 || strlen(nonce_in) >= sizeof nonce)
            return -1;
        memcpy(nonce, nonce_in, strlen(nonce_in) + 1);
    } else if (new_nonce(nonce) != 0) {
        return -1;
    }
    int64_t ts = at_ms ? at_ms : wall_ms();
    char canon[2400];
    int cl = pp_reqsig_canonical(canon, sizeof canon, method, target, body, body_len, ts, nonce, recipient_id);
    if (cl < 0)
        return -1;
    unsigned char sig[64];
    char sig64[100], kid[65];
    if (s->sign(s->user, canon, (size_t)cl, sig) != 0)
        return -1;
    pp_key_id(s->pub, kid);
    if (!pp_base64_encode(sig, 64, sig64, sizeof sig64))
        return -1;
    int n = snprintf(out, cap, "v1 id=%s; kid=%s; ts=%lld; nonce=%s; sig=%s", s->id, kid, (long long)ts, nonce, sig64);
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

/* copy [p, p+len) into out if it is 1..cap-1 bytes */
static int field(const char *p, size_t len, char *out, size_t cap)
{
    if (len == 0 || len >= cap)
        return -1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

/* Split "<sep0><v0><sep1><v1>..." strictly into `n` values. */
static int split(const char *header, size_t max, const char *const *seps, int n, char vals[][120])
{
    if (!header || strlen(header) > max)
        return -1;
    const char *p = header;
    for (int i = 0; i < n; i++) {
        size_t sl = strlen(seps[i]);
        if (strncmp(p, seps[i], sl) != 0)
            return -1;
        p += sl;
        const char *end = i < n - 1 ? strstr(p, seps[i + 1]) : header + strlen(header);
        if (!end || field(p, (size_t)(end - p), vals[i], sizeof vals[i]) != 0)
            return -1;
        p = end;
    }
    return 0;
}

int pp_reqsig_parse(const char *header, pp_reqsig *out)
{
    static const char *const seps[] = { "v1 id=", "; kid=", "; ts=", "; nonce=", "; sig=" };
    char vals[5][120];
    if (split(header, 1000, seps, 5, vals) != 0)
        return -1;
    pp_reqsig r;
    memset(&r, 0, sizeof r);
    unsigned char kidraw[32], tmp[72];
    size_t n = 0;
    if (!pp_id_valid(vals[0]) || pp_hex_decode(vals[1], kidraw, 32) != 0)
        return -1;
    if (strlen(vals[2]) > 15)
        return -1;
    for (const char *c = vals[2]; *c; c++)
        if (*c < '0' || *c > '9')
            return -1;
    if (strlen(vals[3]) < 16 || strlen(vals[3]) >= sizeof r.nonce)
        return -1;
    for (const char *c = vals[3]; *c; c++)
        if (!((*c >= 'A' && *c <= 'Z') || (*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '+' || *c == '/' || *c == '='))
            return -1;
    if (pp_base64_decode(vals[4], tmp, sizeof tmp, &n) != 0 || n != 64)
        return -1;
    memcpy(r.id, vals[0], sizeof r.id);
    memcpy(r.kid, vals[1], 65);
    r.ts = strtoll(vals[2], NULL, 10);
    memcpy(r.nonce, vals[3], strlen(vals[3]) + 1);
    memcpy(r.sig, tmp, 64);
    if (out)
        *out = r;
    return 0;
}

/* ------------------------------------------------------------ replay memory */

typedef struct {
    char key[100];
    int64_t expires;
} slot;

struct pp_replay {
    std::mutex mu;
    size_t cap = 0, used = 0;
    slot *slots = nullptr;
};

pp_replay *pp_replay_new(size_t capacity)
{
    if (capacity == 0)
        capacity = 65536;
    if (capacity < 8 || (capacity & (capacity - 1)) != 0)
        return NULL;
    pp_replay *r = new (std::nothrow) pp_replay();
    if (!r)
        return NULL;
    r->slots = (slot *)calloc(capacity, sizeof *r->slots);
    if (!r->slots) {
        delete r;
        return NULL;
    }
    r->cap = capacity;
    return r;
}

void pp_replay_free(pp_replay *r)
{
    if (!r)
        return;
    free(r->slots);
    delete r;
}

static size_t hash_key(const char *k)
{
    uint64_t h = 1469598103934665603ULL;
    for (; *k; k++)
        h = (h ^ (unsigned char)*k) * 1099511628211ULL;
    return (size_t)h;
}

static void insert_raw(slot *slots, size_t cap, const char *key, int64_t expires)
{
    size_t i = hash_key(key) & (cap - 1);
    while (slots[i].key[0])
        i = (i + 1) & (cap - 1);
    snprintf(slots[i].key, sizeof slots[i].key, "%s", key);
    slots[i].expires = expires;
}

static void purge(pp_replay *r, int64_t now)
{
    slot *fresh = (slot *)calloc(r->cap, sizeof *fresh);
    if (!fresh)
        return;
    size_t used = 0;
    for (size_t i = 0; i < r->cap; i++)
        if (r->slots[i].key[0] && r->slots[i].expires > now) {
            insert_raw(fresh, r->cap, r->slots[i].key, r->slots[i].expires);
            used++;
        }
    free(r->slots);
    r->slots = fresh;
    r->used = used;
}

static pp_authn remember(pp_replay *r, const char *sender, const char *nonce, int64_t now)
{
    char key[100];
    snprintf(key, sizeof key, "%.*s:%.31s", PP_ID_LEN, sender, nonce);
    std::lock_guard<std::mutex> lock(r->mu);
    size_t i = hash_key(key) & (r->cap - 1);
    while (r->slots[i].key[0]) {
        if (strcmp(r->slots[i].key, key) == 0) {
            if (r->slots[i].expires > now)
                return PP_AUTHN_REPLAYED;
            r->slots[i].expires = now + NONCE_REMEMBER_MS;
            return PP_AUTHN_OK;
        }
        i = (i + 1) & (r->cap - 1);
    }
    if ((r->used + 1) * 2 > r->cap) {
        purge(r, now);
        if ((r->used + 1) * 2 > r->cap)
            return PP_AUTHN_BUSY;
    }
    insert_raw(r->slots, r->cap, key, now + NONCE_REMEMBER_MS);
    r->used++;
    return PP_AUTHN_OK;
}

pp_authn pp_reqsig_fresh(const pp_reqsig *r, pp_replay *replay, int64_t at_ms)
{
    int64_t now = at_ms ? at_ms : wall_ms();
    int64_t skew = now - r->ts;
    if (skew > PP_SIG_WINDOW_MS || skew < -PP_SIG_WINDOW_MS)
        return PP_AUTHN_SKEW;
    return replay ? remember(replay, r->id, r->nonce, now) : PP_AUTHN_OK;
}

pp_authn pp_reqsig_authenticate(const char *header, const char *method, const char *target, const void *body, size_t body_len,
                                const char *my_id, pp_key_lookup_fn lookup, void *user, pp_replay *replay, int64_t at_ms,
                                pp_reqsig *out)
{
    pp_reqsig r;
    if (!method || !target || !my_id || !header || pp_reqsig_parse(header, &r) != 0)
        return PP_AUTHN_REJECT;
    unsigned char pub[32];
    char kid_check[65];
    if (!lookup || !lookup(user, r.id, r.kid, pub))
        return PP_AUTHN_REJECT;
    pp_key_id(pub, kid_check);
    if (strcmp(kid_check, r.kid) != 0)
        return PP_AUTHN_REJECT;
    char canon[2400];
    int cl = pp_reqsig_canonical(canon, sizeof canon, method, target, body, body_len, r.ts, r.nonce, my_id);
    if (cl < 0 || !pp_ed25519_verify(pub, canon, (size_t)cl, r.sig))
        return PP_AUTHN_REJECT;
    if (out)
        *out = r;
    return pp_reqsig_fresh(&r, replay, at_ms);
}

/* ------------------------------------------------------------ receipts and custody receipts */

static int receipt_canonical(char *out, size_t cap, const char *id, const char *nonce, int status, const char *body_hash)
{
    int n = snprintf(out, cap, "puddle-receipt-v2\n%s\n%s\n%d\n%s", id, nonce, status, body_hash);
    return (n > 0 && (size_t)n < cap) ? n : -1;
}

static int custody_canonical(char *out, size_t cap, const char *for_id, const char *levee_id, const char *nonce, const char *body_hash)
{
    int n = snprintf(out, cap, "puddle-custody-v1\n%s\n%s\n%s\n%s", for_id, levee_id, nonce, body_hash);
    return (n > 0 && (size_t)n < cap) ? n : -1;
}

int pp_receipt_sign(const pp_signer *s, const char *nonce, int status, const char *body_hash_hex, char *out, size_t cap)
{
    if (!s || !s->id || !s->sign || !nonce || !*nonce || strlen(nonce) > 60 || !is_hex64(body_hash_hex) || status < 100 || status > 599)
        return -1;
    char kid[65], canon[400], sig64[100];
    unsigned char sig[64];
    pp_key_id(s->pub, kid);
    int cl = receipt_canonical(canon, sizeof canon, s->id, nonce, status, body_hash_hex);
    if (cl < 0 || s->sign(s->user, canon, (size_t)cl, sig) != 0 || !pp_base64_encode(sig, 64, sig64, sizeof sig64))
        return -1;
    int n = snprintf(out, cap, "v2 id=%s; kid=%s; sig=%s", s->id, kid, sig64);
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

pp_receipt_check pp_receipt_verify(const char *header, const char *peer_id, const unsigned char peer_pub[32], const char *nonce, int status,
                                   const char *body_hash_hex)
{
    if (!is_hex64(body_hash_hex))
        return PP_RECEIPT_BAD;
    if (!header || !*header)
        return PP_RECEIPT_MISSING;
    static const char *const seps[] = { "v2 id=", "; kid=", "; sig=" };
    char vals[3][120];
    if (strlen(header) >= PP_RECEIPT_MAX || !peer_id || !peer_pub || !nonce || split(header, PP_RECEIPT_MAX, seps, 3, vals) != 0)
        return PP_RECEIPT_BAD;
    unsigned char sig[72];
    size_t sl = 0;
    if (!pp_id_valid(vals[0]) || !is_hex64(vals[1]) || pp_base64_decode(vals[2], sig, sizeof sig, &sl) != 0 || sl != 64)
        return PP_RECEIPT_BAD;
    char want_kid[65];
    pp_key_id(peer_pub, want_kid);
    if (strcmp(vals[0], peer_id) != 0 || strcmp(vals[1], want_kid) != 0)
        return PP_RECEIPT_WRONG_KEY;
    char canon[400];
    int cl = receipt_canonical(canon, sizeof canon, vals[0], nonce, status, body_hash_hex);
    if (cl < 0 || !pp_ed25519_verify(peer_pub, canon, (size_t)cl, sig))
        return PP_RECEIPT_BAD;
    return PP_RECEIPT_OK;
}

int pp_custody_sign(const pp_signer *s, const char *for_id, const char *nonce, const char *body_hash_hex, char *out, size_t cap)
{
    if (!s || !s->id || !s->sign || !pp_id_valid(for_id) || !nonce || !*nonce || strlen(nonce) > 60 || !is_hex64(body_hash_hex))
        return -1;
    char canon[400], sig64[100];
    unsigned char sig[64];
    int cl = custody_canonical(canon, sizeof canon, for_id, s->id, nonce, body_hash_hex);
    if (cl < 0 || s->sign(s->user, canon, (size_t)cl, sig) != 0 || !pp_base64_encode(sig, 64, sig64, sizeof sig64))
        return -1;
    int n = snprintf(out, cap, "v1 for=%s; levee=%s; sig=%s", for_id, s->id, sig64);
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

pp_receipt_check pp_custody_verify(const char *header, const char *for_id, const char *levee_id, const unsigned char levee_pub[32],
                                   const char *nonce, const char *body_hash_hex)
{
    if (!is_hex64(body_hash_hex))
        return PP_RECEIPT_BAD;
    if (!header || !*header)
        return PP_RECEIPT_MISSING;
    static const char *const seps[] = { "v1 for=", "; levee=", "; sig=" };
    char vals[3][120];
    if (!for_id || !levee_id || !levee_pub || !nonce || split(header, PP_CUSTODY_MAX, seps, 3, vals) != 0)
        return PP_RECEIPT_BAD;
    unsigned char sig[72];
    size_t sl = 0;
    if (!pp_id_valid(vals[0]) || !pp_id_valid(vals[1]) || pp_base64_decode(vals[2], sig, sizeof sig, &sl) != 0 || sl != 64)
        return PP_RECEIPT_BAD;
    char want[PP_ID_LEN + 1];
    pp_key_id_b32(PP_LABEL_LEVEE, levee_pub, want);
    if (strcmp(vals[0], for_id) != 0 || strcmp(vals[1], levee_id) != 0 || strcmp(want, levee_id) != 0)
        return PP_RECEIPT_WRONG_KEY;
    char canon[400];
    int cl = custody_canonical(canon, sizeof canon, vals[0], vals[1], nonce, body_hash_hex);
    if (cl < 0 || !pp_ed25519_verify(levee_pub, canon, (size_t)cl, sig))
        return PP_RECEIPT_BAD;
    return PP_RECEIPT_OK;
}

/* ------------------------------------------------------------ sealed requests (spec/09) */

size_t pp_seal_info(const char *sender_id, const char *recipient_id, const char *nonce, char *out, size_t cap)
{
    int n = snprintf(out, cap, "puddle-seal-v1\n%s\n%s\n%s", sender_id, recipient_id, nonce);
    return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}

size_t pp_seal_aad(const char *method, const char *target, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s\n%s", method, target);
    return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}

void pp_sealed_request_free(pp_sealed_request *r)
{
    if (!r)
        return;
    free(r->body);
    OPENSSL_cleanse(r->answer_key, sizeof r->answer_key);
    memset(r, 0, sizeof *r);
}

int pp_seal_request(const pp_signer *s, const char *method, const char *target, const void *body, size_t body_len,
                    const char *recipient_id, const unsigned char seal_pub[32], int64_t at_ms, pp_sealed_request *out)
{
    memset(out, 0, sizeof *out);
    char info[200], aad[1200], kid[65], enc64[64];
    unsigned char enc[PP_SEAL_ENC_LEN];
    pp_hpke ctx;
    size_t il, al;
    if (!s || !s->id || !recipient_id || new_nonce(out->nonce) != 0 || !(il = pp_seal_info(s->id, recipient_id, out->nonce, info, sizeof info)) ||
        !(al = pp_seal_aad(method, target, aad, sizeof aad)) || pp_hpke_sender(seal_pub, info, il, enc, &ctx) != 0)
        return -1;
    int rc = -1;
    if (body_len) {
        out->body = (unsigned char *)malloc(body_len + PP_SEAL_TAG_LEN);
        if (!out->body || pp_hpke_seal(&ctx, aad, al, body, body_len, out->body) != 0)
            goto done;
        out->body_len = body_len + PP_SEAL_TAG_LEN;
    }
    pp_sha256_hex(seal_pub, 32, kid);
    if (!pp_base64_encode(enc, sizeof enc, enc64, sizeof enc64) || pp_seal_answer_key(&ctx, out->answer_key) != 0 ||
        snprintf(out->seal, sizeof out->seal, "v1 kid=%s; enc=%s", kid, enc64) >= (int)sizeof out->seal ||
        pp_reqsig_sign(s, method, target, out->body, out->body_len, recipient_id, at_ms, out->nonce, out->signature, sizeof out->signature) != 0)
        goto done;
    rc = 0;
done:
    OPENSSL_cleanse(&ctx, sizeof ctx);
    if (rc != 0)
        pp_sealed_request_free(out);
    return rc;
}

int pp_seal_header_parse(const char *header, char kid[65], unsigned char enc[PP_SEAL_ENC_LEN])
{
    static const char *const seps[] = { "v1 kid=", "; enc=" };
    char vals[2][120];
    if (!header || strlen(header) >= 160 || split(header, 160, seps, 2, vals) != 0)
        return -1;
    size_t n = 0;
    if (!is_hex64(vals[0]) || pp_base64_decode(vals[1], enc, PP_SEAL_ENC_LEN, &n) != 0 || n != PP_SEAL_ENC_LEN)
        return -1;
    memcpy(kid, vals[0], 65);
    return 0;
}

int pp_open_request(const char *seal_header, const unsigned char sk[32], const char *sender_id, const char *recipient_id, const char *nonce,
                    const char *method, const char *target, const unsigned char *body, size_t body_len, unsigned char *out,
                    unsigned char answer_key[32])
{
    char kid[65], info[200], aad[1200], mine[65];
    unsigned char enc[PP_SEAL_ENC_LEN], pk[32];
    pp_hpke ctx;
    size_t il, al;
    if (pp_seal_header_parse(seal_header, kid, enc) != 0 || pp_x25519_public(sk, pk) != 0)
        return -1;
    pp_sha256_hex(pk, 32, mine);
    if (strcmp(kid, mine) != 0 || !(il = pp_seal_info(sender_id, recipient_id, nonce, info, sizeof info)) ||
        !(al = pp_seal_aad(method, target, aad, sizeof aad)) || pp_hpke_receiver(enc, sk, info, il, &ctx) != 0)
        return -1;
    int rc = -1;
    if (body_len && (body_len < PP_SEAL_TAG_LEN || pp_hpke_open(&ctx, aad, al, body, body_len, out) != 0))
        goto done;
    if (answer_key && pp_seal_answer_key(&ctx, answer_key) != 0)
        goto done;
    rc = 0;
done:
    OPENSSL_cleanse(&ctx, sizeof ctx);
    return rc;
}

/* ------------------------------------------------------------ pieces */

int pp_seal_piece(const unsigned char key[32], uint64_t piece, int status, const void *pt, size_t len, unsigned char *out)
{
    const unsigned char *p = (const unsigned char *)pt;
    size_t at = 0, k = 0;
    do {
        size_t take = len - at < PP_SEAL_RECORD ? len - at : PP_SEAL_RECORD;
        int last = at + take == len;
        if (k >= 64 || pp_seal_record(key, piece * 64 + k, status, last, p + at, take, out) != 0)
            return -1;
        out += take + PP_SEAL_TAG_LEN;
        at += take, k++;
    } while (at < len);
    return 0;
}

int pp_open_piece(const unsigned char key[32], uint64_t piece, int status, const unsigned char *ct, size_t len, unsigned char *out,
                  size_t *out_len)
{
    size_t at = 0, k = 0, w = 0;
    while (at < len) {
        size_t take = len - at < PP_SEAL_RECORD + PP_SEAL_TAG_LEN ? len - at : PP_SEAL_RECORD + PP_SEAL_TAG_LEN;
        int last = at + take == len;
        if (take < PP_SEAL_TAG_LEN || k >= 64 || pp_open_record(key, piece * 64 + k, status, last, ct + at, take, out + w) != 0)
            return -1;
        w += take - PP_SEAL_TAG_LEN;
        at += take, k++;
    }
    if (at == 0)
        return -1;
    *out_len = w;
    return 0;
}
