/* Key chains (spec/01): one record per line, each following the one before. */

#include "puddle_proto.h"
#include "json.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define MAX_CHAIN_BYTES (4u << 20)
#define MAX_CHAIN_RECORDS 10000

static int cfail(char *err, size_t errlen, size_t line, const char *what)
{
    if (err && errlen)
        snprintf(err, errlen, "identity chain record %zu: %s", line, what);
    return -1;
}

static int get_key(const char *rec, size_t len, const char *name, unsigned char out[32])
{
    pp_span v;
    char text[64];
    size_t n = 0;
    unsigned char tmp[40];
    if (pp_json_member(rec, len, name, &v) != 0 || pp_json_string(v, text, sizeof text) != 0 ||
        pp_base64_decode(text, tmp, sizeof tmp, &n) != 0 || n != 32)
        return -1;
    memcpy(out, tmp, 32);
    return 0;
}

static int get_hex64(const char *rec, size_t len, const char *name, char out[65])
{
    pp_span v;
    unsigned char raw[32];
    if (pp_json_member(rec, len, name, &v) != 0 || pp_json_string(v, out, 65) != 0 || pp_hex_decode(out, raw, 32) != 0)
        return -1;
    return 0;
}

static int get_sig(const char *line, size_t len, const char *name, unsigned char out[64])
{
    pp_span v;
    char text[100];
    size_t n = 0;
    unsigned char tmp[72];
    if (pp_json_member(line, len, name, &v) != 0 || pp_json_string(v, text, sizeof text) != 0 ||
        pp_base64_decode(text, tmp, sizeof tmp, &n) != 0 || n != 64)
        return -1;
    memcpy(out, tmp, 64);
    return 0;
}

int pp_chain_verify(const char *text, size_t len, const char *expected_id, pp_chain_head *out, char *err, size_t errlen)
{
    if (!text || len == 0 || len > MAX_CHAIN_BYTES)
        return cfail(err, errlen, 0, "empty or too large");

    pp_chain_head h;
    memset(&h, 0, sizeof h);
    size_t count = 0, pos = 0;

    while (pos < len) {
        const char *line = text + pos;
        const char *nl = (const char *)memchr(line, '\n', len - pos);
        size_t ll = nl ? (size_t)(nl - line) : len - pos;
        pos += ll + (nl ? 1 : 0);
        if (ll == 0)
            continue;
        if (++count > MAX_CHAIN_RECORDS)
            return cfail(err, errlen, count, "too many records");

        pp_span rv;
        char type[32];
        unsigned char sig[64];
        int64_t seq;
        if (!pp_json_valid_object(line, ll) || pp_json_member(line, ll, "record", &rv) != 0 || rv.len == 0 || rv.p[0] != '{' ||
            get_sig(line, ll, "sig", sig) != 0)
            return cfail(err, errlen, count, "malformed");

        const char *rec = rv.p;
        size_t rl = rv.len;
        pp_span t;
        if (pp_json_member(rec, rl, "type", &t) != 0 || pp_json_string(t, type, sizeof type) != 0 ||
            pp_json_member(rec, rl, "seq", &t) != 0 || pp_json_int64(t, &seq) != 0)
            return cfail(err, errlen, count, "missing type or seq");

        unsigned char sp[32], ep[32];
        char next[65];
        if (get_key(rec, rl, "signing", sp) != 0 || get_key(rec, rl, "encryption", ep) != 0 || get_hex64(rec, rl, "next", next) != 0)
            return cfail(err, errlen, count, "bad keys or commitment");

        if (count == 1) {
            if (strcmp(type, "identity.inception") != 0 || seq != 0)
                return cfail(err, errlen, count, "the chain must start with an inception record");
            unsigned char commit_raw[32];
            pp_hex_decode(next, commit_raw, 32);
            pp_user_id(sp, commit_raw, h.id);
            if (expected_id && strcmp(expected_id, h.id) != 0)
                return cfail(err, errlen, count, "this chain belongs to a different id");
            if (!pp_ed25519_verify(sp, rec, rl, sig))
                return cfail(err, errlen, count, "bad signature");
        } else {
            char prev[65], roll_hash[65];
            unsigned char roll_pub[32], sig_roll[64], sig_prev[64];
            if (strcmp(type, "identity.rotate") != 0 || seq < 0 || (uint64_t)seq != h.seq + 1)
                return cfail(err, errlen, count, "out of order");
            if (get_hex64(rec, rl, "prev", prev) != 0 || strcmp(prev, h.head_hash) != 0)
                return cfail(err, errlen, count, "does not follow the previous record");
            if (get_key(rec, rl, "roll", roll_pub) != 0 || get_sig(line, ll, "sig_roll", sig_roll) != 0 ||
                get_sig(line, ll, "sig_prev", sig_prev) != 0)
                return cfail(err, errlen, count, "malformed");
            pp_sha256_hex(roll_pub, 32, roll_hash);
            if (strcmp(roll_hash, h.next) != 0)
                return cfail(err, errlen, count, "the roll key is not the one the previous record committed to");
            if (!pp_ed25519_verify(roll_pub, rec, rl, sig_roll))
                return cfail(err, errlen, count, "bad signature from the roll key");
            if (!pp_ed25519_verify(sp, rec, rl, sig))
                return cfail(err, errlen, count, "bad signature from the new key");
            if (!pp_ed25519_verify(h.sign_pub, rec, rl, sig_prev))
                return cfail(err, errlen, count, "bad signature from the previous key");
        }

        h.seq = (uint64_t)seq;
        memcpy(h.sign_pub, sp, 32);
        memcpy(h.enc_pub, ep, 32);
        memcpy(h.next, next, 65);
        pp_sha256_hex(rec, rl, h.head_hash);
    }
    if (count == 0)
        return cfail(err, errlen, 0, "empty");
    *out = h;
    return 0;
}
