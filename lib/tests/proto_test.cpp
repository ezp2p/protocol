/* libpuddle-proto against the protocol's vectors (../vectors), RFC 9180's own, and round trips of everything else.
 * With PP_WRITE_VECTORS=<the vectors folder> it writes levee.json and chains.json afresh (only when the protocol changes). */

#include "puddle_proto.h"
#include "../src/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

static int failures;
#define CHECK(cond) do { if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

static size_t unhex(const char *s, unsigned char *out)
{
    size_t n = 0;
    for (; s[0] && s[1]; s += 2) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (unsigned char)v;
    }
    return n;
}

static int same_hex(const unsigned char *b, size_t len, const char *hex)
{
    unsigned char want[256];
    return unhex(hex, want) == len && memcmp(b, want, len) == 0;
}

static std::string hexs(const unsigned char *b, size_t n)
{
    std::string s(2 * n, '\0');
    pp_hex_encode(b, (unsigned)n, &s[0]);
    s.resize(2 * n);
    return s;
}

static std::string slurp(const std::string &path)
{
    std::string s;
    FILE *f = fopen(path.c_str(), "rb");
    if (!f)
        return s;
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        s.append(buf, n);
    fclose(f);
    return s;
}

static std::string str(const char *json, size_t len, const char *key)
{
    pp_span v;
    static char buf[1 << 16];
    if (pp_json_member(json, len, key, &v) != 0 || pp_json_string(v, buf, sizeof buf) != 0)
        return "";
    return buf;
}

static int64_t num(const char *json, size_t len, const char *key)
{
    pp_span v;
    int64_t n = -1;
    if (pp_json_member(json, len, key, &v) != 0 || pp_json_int64(v, &n) != 0)
        return -1;
    return n;
}

static std::vector<pp_span> items(const char *json, size_t len, const char *key)
{
    std::vector<pp_span> out;
    pp_span arr, it;
    size_t cur = 0;
    if (pp_json_member(json, len, key, &arr) != 0)
        return out;
    while (pp_json_array_next(arr, &cur, &it) == 1)
        out.push_back(it);
    return out;
}

static pp_span member(const char *json, size_t len, const char *key)
{
    pp_span v = { "", 0 };
    pp_json_member(json, len, key, &v);
    return v;
}

static void test_rfc9180(void)
{
    unsigned char info[64], ikm_e[32], ikm_r[32], sk_e[32], pk_e[32], sk_r[32], pk_r[32], enc[32];
    size_t info_len = unhex("4f6465206f6e2061204772656369616e2055726e", info);
    unhex("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b", ikm_e);
    unhex("1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df", ikm_r);

    CHECK(pp_x25519_derive(ikm_e, 32, sk_e, pk_e) == 0);
    CHECK(same_hex(sk_e, 32, "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600"));
    CHECK(same_hex(pk_e, 32, "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"));
    CHECK(pp_x25519_derive(ikm_r, 32, sk_r, pk_r) == 0);
    CHECK(same_hex(sk_r, 32, "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb"));
    CHECK(same_hex(pk_r, 32, "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"));

    pp_hpke s, r;
    CHECK(pp_hpke_sender_with(sk_e, pk_r, info, info_len, enc, &s) == 0);
    CHECK(same_hex(enc, 32, "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"));
    CHECK(same_hex(s.key, 32, "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91"));
    CHECK(same_hex(s.base_nonce, 12, "5c4d98150661b848853b547f"));
    CHECK(same_hex(s.exporter, 32, "a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922"));
    CHECK(pp_hpke_receiver(enc, sk_r, info, info_len, &r) == 0);
    CHECK(memcmp(s.key, r.key, 32) == 0 && memcmp(s.base_nonce, r.base_nonce, 12) == 0 && memcmp(s.exporter, r.exporter, 32) == 0);

    /* encryptions: sequence numbers 0, 1, 2, 4, 255, 256 */
    static const struct { unsigned seq; const char *aad, *ct; } enc_vectors[] = {
        { 0, "436f756e742d30", "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28" },
        { 1, "436f756e742d31", "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c" },
        { 2, "436f756e742d32", "71146bd6795ccc9c49ce25dda112a48f202ad220559502cef1f34271e0cb4b02b4f10ecac6f48c32f878fae86b" },
        { 4, "436f756e742d34", "63357a2aa291f5a4e5f27db6baa2af8cf77427c7c1a909e0b37214dd47db122bb153495ff0b02e9e54a50dbe16" },
        { 255, "436f756e742d323535", "18ab939d63ddec9f6ac2b60d61d36a7375d2070c9b683861110757062c52b8880a5f6b3936da9cd6c23ef2a95c" },
        { 256, "436f756e742d323536", "7a4a13e9ef23978e2c520fd4d2e757514ae160cd0cd05e556ef692370ca53076214c0c40d4c728d6ed9e727a5b" },
    };
    unsigned char pt[64], aad[16], ct[128], back[128];
    size_t pt_len = unhex("4265617574792069732074727574682c20747275746820626561757479", pt);
    for (size_t i = 0; i < sizeof enc_vectors / sizeof enc_vectors[0]; i++) {
        size_t aad_len = unhex(enc_vectors[i].aad, aad);
        s.seq = r.seq = enc_vectors[i].seq;
        CHECK(pp_hpke_seal(&s, aad, aad_len, pt, pt_len, ct) == 0);
        CHECK(same_hex(ct, pt_len + PP_SEAL_TAG_LEN, enc_vectors[i].ct));
        CHECK(pp_hpke_open(&r, aad, aad_len, ct, pt_len + PP_SEAL_TAG_LEN, back) == 0 && memcmp(back, pt, pt_len) == 0);
        CHECK(s.seq == enc_vectors[i].seq + 1 && r.seq == s.seq);
    }

    /* exports */
    unsigned char out[32], label[16];
    CHECK(pp_hpke_export(&s, "", 0, out, 32) == 0);
    CHECK(same_hex(out, 32, "4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e"));
    label[0] = 0;
    CHECK(pp_hpke_export(&s, label, 1, out, 32) == 0);
    CHECK(same_hex(out, 32, "8c1df14732580e5501b00f82b10a1647b40713191b7c1240ac80e2b68808ba69"));
    size_t ll = unhex("54657374436f6e74657874", label);
    CHECK(pp_hpke_export(&r, label, ll, out, 32) == 0);
    CHECK(same_hex(out, 32, "5acb09211139c43b3090489a9da433e8a30ee7188ba8b0a9a1ccf0c229283e53"));
}

/* ------------------------------------------------------------------ the protocol's vectors */

static std::string vectors_dir;

static void test_signatures(void)
{
    std::string j = slurp(vectors_dir + "/signatures.json");
    CHECK(!j.empty());
    const char *t = j.c_str();
    size_t n = j.size();
    int64_t now = num(t, n, "now_ms");
    pp_span snd = member(t, n, "sender"), rsp = member(t, n, "responder");
    std::string sid = str(snd.p, snd.len, "id"), rid = str(rsp.p, rsp.len, "id");
    static unsigned char spub[32], rpub[32];
    unhex(str(snd.p, snd.len, "public_key").c_str(), spub);
    unhex(str(rsp.p, rsp.len, "public_key").c_str(), rpub);
    struct Look { std::string id; const unsigned char *pub; } look = { sid, spub };
    auto lookup = [](void *u, const char *id, const char *kid, unsigned char out[32]) -> int {
        Look *l = (Look *)u;
        char k[65];
        pp_key_id(l->pub, k);
        if (l->id != id || strcmp(k, kid) != 0)
            return 0;
        memcpy(out, l->pub, 32);
        return 1;
    };
    int count = 0;
    for (pp_span it : items(t, n, "requests")) {
        std::string body = str(it.p, it.len, "body"), expect = str(it.p, it.len, "expect");
        std::string who = str(it.p, it.len, "checked_by");
        pp_span any = member(it.p, it.len, "accepts_any");
        bool accepts_any = any.len == 4 && !memcmp(any.p, "true", 4);
        pp_authn a = pp_reqsig_authenticate(str(it.p, it.len, "header").c_str(), str(it.p, it.len, "method").c_str(),
                                            str(it.p, it.len, "target").c_str(), body.data(), body.size(), who.c_str(), lookup, &look,
                                            NULL, now, NULL);
        if (a == PP_AUTHN_REJECT && accepts_any)
            a = pp_reqsig_authenticate(str(it.p, it.len, "header").c_str(), str(it.p, it.len, "method").c_str(),
                                       str(it.p, it.len, "target").c_str(), body.data(), body.size(), PP_RECIPIENT_ANY, lookup, &look,
                                       NULL, now, NULL);
        const char *got = a == PP_AUTHN_OK ? "ok" : a == PP_AUTHN_SKEW ? "clock_skew" : "reject";
        if (expect != got)
            fprintf(stderr, "request vector \"%s\": want %s, got %s\n", str(it.p, it.len, "name").c_str(), expect.c_str(), got);
        CHECK(expect == got);
        count++;
    }
    for (pp_span it : items(t, n, "receipts")) {
        std::string body = str(it.p, it.len, "body"), expect = str(it.p, it.len, "expect");
        char h[65];
        pp_sha256_hex(body.data(), body.size(), h);
        pp_receipt_check c = pp_receipt_verify(str(it.p, it.len, "header").c_str(), rid.c_str(), rpub, str(it.p, it.len, "nonce").c_str(),
                                               (int)num(it.p, it.len, "status"), h);
        const char *got = c == PP_RECEIPT_OK ? "ok" : c == PP_RECEIPT_MISSING ? "missing" : c == PP_RECEIPT_WRONG_KEY ? "wrong_key" : "bad";
        if (expect != got)
            fprintf(stderr, "receipt vector \"%s\": want %s, got %s\n", str(it.p, it.len, "name").c_str(), expect.c_str(), got);
        CHECK(expect == got);
        count++;
    }
    CHECK(count >= 10);
}

static void test_devices(void)
{
    std::string j = slurp(vectors_dir + "/devices.json");
    CHECK(!j.empty());
    int count = 0;
    for (pp_span it : items(j.c_str(), j.size(), "devices")) {
        unsigned char seed[32], pub[32];
        char id[PP_ID_LEN + 1];
        unhex(str(it.p, it.len, "seed").c_str(), seed);
        CHECK(pp_ed25519_public(seed, pub) == 0);
        CHECK(hexs(pub, 32) == str(it.p, it.len, "public_key"));
        pp_key_id_b32(PP_LABEL_DEVICE, pub, id);
        CHECK(str(it.p, it.len, "id") == id);
        count++;
    }
    CHECK(count > 0);
}

/* ------------------------------------------------------------------ chains: made here from fixed seeds */

struct Keys {
    unsigned char sign[32], enc_sk[32], enc_pk[32], roll[32];
};

static void keys_from(int n, Keys &k)
{
    for (int i = 0; i < 32; i++) {
        k.sign[i] = (unsigned char)(n * 3 + i);
        k.roll[i] = (unsigned char)(n * 5 + 2 * i + 1);
    }
    unsigned char ikm[32];
    for (int i = 0; i < 32; i++)
        ikm[i] = (unsigned char)(n * 7 + i + 9);
    pp_x25519_derive(ikm, 32, k.enc_sk, k.enc_pk);
}

static std::string b64(const unsigned char *b, size_t n)
{
    char out[200];
    pp_base64_encode(b, n, out, sizeof out);
    return out;
}

static std::string sig_of(const unsigned char seed[32], const std::string &rec)
{
    unsigned char s[64];
    pp_ed25519_sign(seed, rec.data(), rec.size(), s);
    return b64(s, 64);
}

static std::string pub_of(const unsigned char seed[32])
{
    unsigned char p[32];
    pp_ed25519_public(seed, p);
    return b64(p, 32);
}

static std::string commit_of(const unsigned char seed[32])
{
    unsigned char p[32];
    char h[65];
    pp_ed25519_public(seed, p);
    pp_sha256_hex(p, 32, h);
    return h;
}

static std::string chain_two(std::string *head_hash1)
{
    Keys a, b;
    keys_from(1, a);
    keys_from(2, b);
    std::string r0 = "{\"type\":\"identity.inception\",\"seq\":0,\"signing\":\"" + pub_of(a.sign) + "\",\"encryption\":\"" + b64(a.enc_pk, 32) +
                     "\",\"next\":\"" + commit_of(a.roll) + "\",\"ts\":1760000000000}";
    char h0[65];
    pp_sha256_hex(r0.data(), r0.size(), h0);
    std::string r1 = "{\"type\":\"identity.rotate\",\"seq\":1,\"prev\":\"" + std::string(h0) + "\",\"signing\":\"" + pub_of(b.sign) +
                     "\",\"encryption\":\"" + b64(b.enc_pk, 32) + "\",\"roll\":\"" + pub_of(a.roll) + "\",\"next\":\"" + commit_of(b.roll) +
                     "\",\"ts\":1760000001000}";
    if (head_hash1) {
        char h1[65];
        pp_sha256_hex(r1.data(), r1.size(), h1);
        *head_hash1 = h1;
    }
    return "{\"record\":" + r0 + ",\"sig\":\"" + sig_of(a.sign, r0) + "\"}\n" + "{\"record\":" + r1 + ",\"sig\":\"" + sig_of(b.sign, r1) +
           "\",\"sig_roll\":\"" + sig_of(a.roll, r1) + "\",\"sig_prev\":\"" + sig_of(a.sign, r1) + "\"}\n";
}

static void test_chains(void)
{
    std::string hh;
    std::string c = chain_two(&hh);
    pp_chain_head h;
    char err[200];
    CHECK(pp_chain_verify(c.data(), c.size(), NULL, &h, err, sizeof err) == 0);
    Keys a, b;
    keys_from(1, a);
    keys_from(2, b);
    unsigned char apub[32], bpub[32], commit[32];
    pp_ed25519_public(a.sign, apub);
    pp_ed25519_public(b.sign, bpub);
    pp_ed25519_public(a.roll, commit);
    pp_sha256(commit, 32, commit);
    char id[PP_ID_LEN + 1];
    pp_user_id(apub, commit, id);
    CHECK(strcmp(h.id, id) == 0 && h.seq == 1 && memcmp(h.sign_pub, bpub, 32) == 0 && memcmp(h.enc_pub, b.enc_pk, 32) == 0);
    CHECK(hh == h.head_hash);
    CHECK(pp_chain_verify(c.data(), c.size(), id, &h, err, sizeof err) == 0);
    CHECK(pp_chain_verify(c.data(), c.size(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &h, err, sizeof err) != 0);
    /* the first record alone is a chain too */
    std::string first = c.substr(0, c.find('\n') + 1);
    CHECK(pp_chain_verify(first.data(), first.size(), id, &h, err, sizeof err) == 0 && h.seq == 0);
    /* any byte changed breaks it */
    std::string bad = c;
    bad[c.find("1760000001000")] = '2';
    CHECK(pp_chain_verify(bad.data(), bad.size(), NULL, &h, err, sizeof err) != 0);
    /* a rotation without the roll key's signature */
    bad = c;
    size_t at = bad.find("\"sig_roll\":\"") + 12;
    bad[at] = bad[at] == 'A' ? 'B' : 'A';
    CHECK(pp_chain_verify(bad.data(), bad.size(), NULL, &h, err, sizeof err) != 0);
}

/* ------------------------------------------------------------------ Levee: ids and custody receipts (spec/06) */

static const unsigned char kLeveeSeed[32] = { 'l', 'e', 'v', 'e', 'e', ' ', 's', 'e', 'e', 'd', ' ', 'f', 'o', 'r', ' ', 't',
                                              'h', 'e', ' ', 'v', 'e', 'c', 't', 'o', 'r', 's', ' ', '.', '.', '.', '.', '.' };

static void test_levee(void)
{
    unsigned char pub[32], sk[32], pk[32];
    char id[PP_ID_LEN + 1];
    CHECK(pp_ed25519_public(kLeveeSeed, pub) == 0);
    pp_key_id_b32(PP_LABEL_LEVEE, pub, id);
    CHECK(pp_seal_key_from_seed(kLeveeSeed, PP_SEAL_INFO_LEVEE, sk, pk) == 0);
    pp_signer s;
    pp_signer_from_seed(&s, id, kLeveeSeed);

    const char *puddle = "xbaaqzgzryy6hzq2czq6vyirhtinnk7tmkidavruesfno5sj6awa", *nonce = "AAECAwQFBgcICQoLDA0ODw==";
    char h[65], hdr[PP_CUSTODY_MAX], other[65];
    pp_sha256_hex("sealed body", 11, h);
    pp_sha256_hex("another body", 12, other);
    CHECK(pp_custody_sign(&s, puddle, nonce, h, hdr, sizeof hdr) == 0);
    CHECK(pp_custody_verify(hdr, puddle, id, pub, nonce, h) == PP_RECEIPT_OK);
    CHECK(pp_custody_verify(hdr, puddle, id, pub, nonce, other) == PP_RECEIPT_BAD);
    CHECK(pp_custody_verify(hdr, puddle, id, pub, "AAECAwQFBgcICQoLDA0ODg==", h) == PP_RECEIPT_BAD);
    CHECK(pp_custody_verify(hdr, "6qxmili24eyrwz3ovjjtml6zbxehkxwrhl2dm4ypu3p7pzecrtcq", id, pub, nonce, h) == PP_RECEIPT_WRONG_KEY);
    CHECK(pp_custody_verify("", puddle, id, pub, nonce, h) == PP_RECEIPT_MISSING);
    unsigned char wrong[32];
    memcpy(wrong, pub, 32);
    wrong[0] ^= 1;
    CHECK(pp_custody_verify(hdr, puddle, id, wrong, nonce, h) == PP_RECEIPT_WRONG_KEY);

    /* the vectors: what another implementation must make from the same seed */
    std::string j = slurp(vectors_dir + "/levee.json");
    const char *w = getenv("PP_WRITE_VECTORS");
    if (w && *w) {
        std::string out = "{\n  \"about\": \"Levees (spec/06-levee.md): from the seed (hex), the Ed25519 public key, the Levee's id, and its sealing key "
                          "(HKDF-SHA256, no salt, info levee-seal-v1, then X25519); and custody receipts, which must check as `expect` for the "
                          "Puddle `for`, the request's `nonce` and the SHA-256 of `body`.\",\n";
        out += "  \"seed\": \"" + hexs(kLeveeSeed, 32) + "\",\n  \"public_key\": \"" + hexs(pub, 32) + "\",\n  \"id\": \"" + id +
               "\",\n  \"seal_public_key\": \"" + hexs(pk, 32) + "\",\n  \"custody\": [\n";
        out += "    {\"name\": \"a good custody receipt\", \"for\": \"" + std::string(puddle) + "\", \"nonce\": \"" + nonce +
               "\", \"body\": \"sealed body\", \"header\": \"" + hdr + "\", \"expect\": \"ok\"},\n";
        out += "    {\"name\": \"another body\", \"for\": \"" + std::string(puddle) + "\", \"nonce\": \"" + nonce +
               "\", \"body\": \"another body\", \"header\": \"" + hdr + "\", \"expect\": \"bad\"},\n";
        out += "    {\"name\": \"for another Puddle\", \"for\": \"6qxmili24eyrwz3ovjjtml6zbxehkxwrhl2dm4ypu3p7pzecrtcq\", \"nonce\": \"" +
               std::string(nonce) + "\", \"body\": \"sealed body\", \"header\": \"" + hdr + "\", \"expect\": \"wrong_key\"},\n";
        out += "    {\"name\": \"none\", \"for\": \"" + std::string(puddle) + "\", \"nonce\": \"" + nonce +
               "\", \"body\": \"sealed body\", \"header\": \"\", \"expect\": \"missing\"}\n  ]\n}\n";
        FILE *f = fopen((std::string(w) + "/levee.json").c_str(), "wb");
        CHECK(f != NULL);
        if (f) {
            fwrite(out.data(), 1, out.size(), f);
            fclose(f);
        }
        j = out;
    }
    CHECK(!j.empty());
    const char *t = j.c_str();
    size_t n = j.size();
    CHECK(str(t, n, "public_key") == hexs(pub, 32) && str(t, n, "id") == id && str(t, n, "seal_public_key") == hexs(pk, 32));
    int count = 0;
    for (pp_span it : items(t, n, "custody")) {
        std::string body = str(it.p, it.len, "body"), expect = str(it.p, it.len, "expect");
        char bh[65];
        pp_sha256_hex(body.data(), body.size(), bh);
        pp_receipt_check c = pp_custody_verify(str(it.p, it.len, "header").c_str(), str(it.p, it.len, "for").c_str(), id, pub,
                                               str(it.p, it.len, "nonce").c_str(), bh);
        const char *got = c == PP_RECEIPT_OK ? "ok" : c == PP_RECEIPT_MISSING ? "missing" : c == PP_RECEIPT_WRONG_KEY ? "wrong_key" : "bad";
        CHECK(expect == got);
        count++;
    }
    CHECK(count == 4);
}

/* ------------------------------------------------------------------ round trips */

static void test_sealed_request(void)
{
    static const unsigned char alice_seed[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                                   17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
    unsigned char apub[32], bsk[32], bpk[32];
    char alice[PP_ID_LEN + 1];
    pp_ed25519_public(alice_seed, apub);
    pp_key_id_b32(PP_LABEL_POND, apub, alice);
    CHECK(pp_x25519_derive("bob's sealing key, thirty-two by", 32, bsk, bpk) == 0);
    const char *bob = "6qxmili24eyrwz3ovjjtml6zbxehkxwrhl2dm4ypu3p7pzecrtcq";
    pp_signer s;
    pp_signer_from_seed(&s, alice, alice_seed);
    pp_sealed_request r;
    const char *body = "{\"hello\":\"bob\"}";
    CHECK(pp_seal_request(&s, "POST", "/stream/v1/events", body, strlen(body), bob, bpk, 0, &r) == 0);

    struct L { const unsigned char *pub; } l = { apub };
    auto lookup = [](void *u, const char *, const char *, unsigned char out[32]) -> int {
        memcpy(out, ((L *)u)->pub, 32);
        return 1;
    };
    pp_replay *rp = pp_replay_new(0);
    pp_reqsig sig;
    CHECK(pp_reqsig_authenticate(r.signature, "POST", "/stream/v1/events", r.body, r.body_len, bob, lookup, &l, rp, 0, &sig) == PP_AUTHN_OK);
    CHECK(pp_reqsig_authenticate(r.signature, "POST", "/stream/v1/events", r.body, r.body_len, bob, lookup, &l, rp, 0, NULL) ==
          PP_AUTHN_REPLAYED);
    CHECK(pp_reqsig_authenticate(r.signature, "POST", "/stream/v1/event", r.body, r.body_len, bob, lookup, &l, NULL, 0, NULL) ==
          PP_AUTHN_REJECT);
    unsigned char plain[64], key[32];
    CHECK(pp_open_request(r.seal, bsk, alice, bob, sig.nonce, "POST", "/stream/v1/events", r.body, r.body_len, plain, key) == 0);
    CHECK(memcmp(plain, body, strlen(body)) == 0 && memcmp(key, r.answer_key, 32) == 0);
    CHECK(pp_open_request(r.seal, bsk, alice, bob, sig.nonce, "POST", "/stream/v1/other", r.body, r.body_len, plain, key) != 0);

    /* the answer, and its receipt */
    std::string ans = "{\"ok\":true}";
    std::vector<unsigned char> sealed(pp_seal_answer_len(ans.size())), back(ans.size() + 1);
    size_t bl = 0;
    CHECK(pp_seal_answer(key, 200, ans.data(), ans.size(), sealed.data()) == 0);
    CHECK(pp_open_answer(r.answer_key, 200, sealed.data(), sealed.size(), back.data(), &bl) == 0 && bl == ans.size());
    CHECK(pp_open_answer(r.answer_key, 404, sealed.data(), sealed.size(), back.data(), &bl) != 0);

    pp_replay_free(rp);
    pp_sealed_request_free(&r);
}

static void test_pieces(void)
{
    unsigned char key[32];
    for (int i = 0; i < 32; i++)
        key[i] = (unsigned char)(200 - i);
    for (size_t len : { (size_t)0, (size_t)5, (size_t)PP_SEAL_RECORD, (size_t)(1 << 20) - 7 }) {
        std::vector<unsigned char> pt(len), ct(pp_seal_answer_len(len)), back(len + 1);
        for (size_t i = 0; i < len; i++)
            pt[i] = (unsigned char)(i * 31);
        size_t bl = 0;
        CHECK(pp_seal_piece(key, 3, 0, pt.data(), len, ct.data()) == 0);
        CHECK(pp_open_piece(key, 3, 0, ct.data(), ct.size(), back.data(), &bl) == 0 && bl == len && memcmp(back.data(), pt.data(), len) == 0);
        CHECK(pp_open_piece(key, 4, 0, ct.data(), ct.size(), back.data(), &bl) != 0);
        CHECK(pp_open_piece(key, PP_PIECE_HASHES, 0, ct.data(), ct.size(), back.data(), &bl) != 0);
        if (ct.size() > 16 + PP_SEAL_TAG_LEN)
            CHECK(pp_open_piece(key, 3, 0, ct.data(), ct.size() - 1, back.data(), &bl) != 0);
    }
}

int main(int argc, char **argv)
{
    vectors_dir = argc > 1 ? argv[1] : "../vectors";
    test_rfc9180();
    test_signatures();
    test_devices();
    test_chains();
    test_levee();
    test_sealed_request();
    test_pieces();
    if (failures)
        fprintf(stderr, "%d failure(s)\n", failures);
    else
        printf("libpuddle-proto: all good\n");
    return failures ? 1 : 0;
}
