/* Ids, Ed25519 and sealing keys (spec/01, spec/09). */

#include "puddle_proto.h"

#include <string.h>

#include <openssl/evp.h>

int pp_id_valid(const char *s)
{
    if (!s || strlen(s) != PP_ID_LEN)
        return 0;
    for (int i = 0; i < PP_ID_LEN; i++)
        if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '2' && s[i] <= '7')))
            return 0;
    return 1;
}

void pp_key_id(const unsigned char pub[32], char out[65])
{
    pp_sha256_hex(pub, 32, out);
}

void pp_key_id_b32(const char *label, const unsigned char pub[32], char out[PP_ID_LEN + 1])
{
    size_t ll = label ? strlen(label) : 0;
    unsigned char buf[64 + 32], h[32];
    if (ll > 64)
        ll = 64;
    if (ll)
        memcpy(buf, label, ll);
    memcpy(buf + ll, pub, 32);
    pp_sha256(buf, ll + 32, h);
    pp_base32_encode(h, 32, out, PP_ID_LEN + 1);
}

void pp_user_id(const unsigned char first_sign_pub[32], const unsigned char first_roll_commit[32], char out[PP_ID_LEN + 1])
{
    unsigned char both[64], h[32];
    memcpy(both, first_sign_pub, 32);
    memcpy(both + 32, first_roll_commit, 32);
    pp_sha256(both, 64, h);
    pp_base32_encode(h, 32, out, PP_ID_LEN + 1);
}

int pp_ed25519_public(const unsigned char seed[32], unsigned char pub[32])
{
    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    size_t n = 32;
    int ok = k && EVP_PKEY_get_raw_public_key(k, pub, &n) == 1 && n == 32;
    EVP_PKEY_free(k);
    return ok ? 0 : -1;
}

int pp_ed25519_sign(const unsigned char seed[32], const void *data, size_t len, unsigned char sig[64])
{
    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t sl = 64;
    int ok = k && ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, k) == 1 &&
             EVP_DigestSign(ctx, sig, &sl, (const unsigned char *)data, len) == 1 && sl == 64;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(k);
    return ok ? 0 : -1;
}

int pp_ed25519_verify(const unsigned char pub[32], const void *data, size_t len, const unsigned char sig[64])
{
    EVP_PKEY *k = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, 32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = k && ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, k) == 1 &&
             EVP_DigestVerify(ctx, sig, 64, (const unsigned char *)data, len) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(k);
    return ok;
}

int pp_seal_key_from_seed(const unsigned char seed[32], const char *info, unsigned char sk[32], unsigned char pk[32])
{
    return pp_hkdf_sha256(seed, 32, "", info, sk, 32) == 0 && pp_x25519_public(sk, pk) == 0 ? 0 : -1;
}

static int seed_sign(void *user, const void *data, size_t len, unsigned char sig[64])
{
    return pp_ed25519_sign((const unsigned char *)user, data, len, sig);
}

void pp_signer_from_seed(pp_signer *s, const char *id, const unsigned char seed[32])
{
    memset(s, 0, sizeof *s);
    s->id = id;
    pp_ed25519_public(seed, s->pub);
    s->sign = seed_sign;
    s->user = (void *)seed;
}
