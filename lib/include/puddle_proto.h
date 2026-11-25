#ifndef PUDDLE_PROTO_H
#define PUDDLE_PROTO_H

/* libpuddle-proto: the bytes of the Puddle Protocol, once, for every program that speaks it (Puddle, Pond, Levee).
 *
 * Ids and key chains (spec/01), request signatures and answer receipts (spec/02), sealing (spec/09) and custody receipts
 * (spec/06). C-callable, OpenSSL 3.0 or later only, no other dependency, no global state but what a caller makes. The test
 * vectors in ../vectors are what it is checked against (tests/vectors_test.cpp).
 *
 * Conventions: functions return 0 on success and -1 on failure unless they say otherwise; checks that answer yes or no
 * return 1 or 0. Ids are 52 characters of base32 (a-z, 2-7). Keys are raw bytes: 32 for Ed25519 and X25519 public keys,
 * 32 for an Ed25519 seed. Hashes in text are 64 lowercase hex characters. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PP_ID_LEN 52
#define PP_RECIPIENT_ANY "*"            /* a request to someone not known yet (spec/02) */
#define PP_SIG_WINDOW_MS (5 * 60 * 1000) /* how far a request's clock may be off */
#define PP_SEALED_TYPE "application/puddle-sealed"

/* ------------------------------------------------------------------ encoding and hashing */

/* RFC 4648 base32, lowercase, no padding. The length written (NUL added), or 0 if `cap` is too small. */
size_t pp_base32_encode(const unsigned char *in, size_t len, char *out, size_t cap);
/* Exactly `len` bytes from base32 that encodes exactly that many. */
int pp_base32_decode(const char *in, unsigned char *out, size_t len);
/* Standard base64 with padding. The length written, or 0. */
size_t pp_base64_encode(const unsigned char *in, size_t len, char *out, size_t cap);
/* Strict: padding required, no whitespace, no stray bits. The count in *outlen. */
int pp_base64_decode(const char *in, unsigned char *out, size_t cap, size_t *outlen);
/* Exactly `n` bytes from 2n lowercase hex characters. */
int pp_hex_decode(const char *hex, unsigned char *out, size_t n);
void pp_hex_encode(const unsigned char *bytes, unsigned len, char *out); /* out: 2*len+1 */
void pp_sha256(const void *data, size_t len, unsigned char out[32]);
void pp_sha256_hex(const void *data, size_t len, char out[65]);
/* HKDF-SHA256 (RFC 5869) with a text salt and info ("" for none). */
int pp_hkdf_sha256(const void *ikm, size_t ikm_len, const char *salt, const char *info, unsigned char *out, size_t outlen);

/* ------------------------------------------------------------------ keys and ids (spec/01) */

/* 1 if `s` is 52 characters of a-z and 2-7. */
int pp_id_valid(const char *s);
/* What a request names as `kid`: hex SHA-256 of a public key. */
void pp_key_id(const unsigned char pub[32], char out[65]);
/* base32(SHA-256(label || pub)): label "" for a Pond, "puddle-device-v1\n" for a phone, "puddle-levee-v1\n" for a Levee. A
 * Puddle's user id is the chain's to say (pp_chain_verify). */
void pp_key_id_b32(const char *label, const unsigned char pub[32], char out[PP_ID_LEN + 1]);
#define PP_LABEL_POND ""
#define PP_LABEL_DEVICE "puddle-device-v1\n"
#define PP_LABEL_LEVEE "puddle-levee-v1\n"

/* Ed25519 from a 32-byte seed. */
int pp_ed25519_public(const unsigned char seed[32], unsigned char pub[32]);
int pp_ed25519_sign(const unsigned char seed[32], const void *data, size_t len, unsigned char sig[64]);
/* 1 valid, 0 not. */
int pp_ed25519_verify(const unsigned char pub[32], const void *data, size_t len, const unsigned char sig[64]);

/* A sealing key (X25519) derived from an Ed25519 seed: HKDF-SHA256, no salt, `info` "pond-seal-v1" or "levee-seal-v1". */
int pp_seal_key_from_seed(const unsigned char seed[32], const char *info, unsigned char sk[32], unsigned char pk[32]);
#define PP_SEAL_INFO_POND "pond-seal-v1"
#define PP_SEAL_INFO_LEVEE "levee-seal-v1"

/* ------------------------------------------------------------------ key chains (spec/01) */

typedef struct {
    char id[PP_ID_LEN + 1];
    uint64_t seq;
    unsigned char sign_pub[32]; /* the current keys */
    unsigned char enc_pub[32];
    char next[65];      /* commitment to the next roll key */
    char head_hash[65]; /* SHA-256 of the last record */
} pp_chain_head;

/* Check a chain (one record per line). With `expected_id`, it must be that id's. The reason in `err` on failure. */
int pp_chain_verify(const char *text, size_t len, const char *expected_id, pp_chain_head *out, char *err, size_t errlen);

/* A Puddle's user id from its first signing key and the commitment to its first roll key (raw SHA-256 of the roll key). */
void pp_user_id(const unsigned char first_sign_pub[32], const unsigned char first_roll_commit[32], char out[PP_ID_LEN + 1]);

/* ------------------------------------------------------------------ signers */

/* Something that signs: `user` is whatever holds the key. 0 or -1. */
typedef int (*pp_sign_fn)(void *user, const void *data, size_t len, unsigned char sig[64]);

typedef struct {
    const char *id;          /* who signs: a user, device, Pond or Levee id */
    unsigned char pub[32];   /* its current signing key */
    pp_sign_fn sign;
    void *user;
} pp_signer;

/* A signer for a key held as a seed (a Pond's, a Levee's, a test's): `seed` must outlive the signer. */
void pp_signer_from_seed(pp_signer *s, const char *id, const unsigned char seed[32]);

/* ------------------------------------------------------------------ request signatures (spec/02) */

typedef struct {
    char id[PP_ID_LEN + 1];
    char kid[65];
    int64_t ts;
    char nonce[48];
    unsigned char sig[64];
} pp_reqsig;

#define PP_REQSIG_MAX 800 /* room for the header value */

/* The header value for a request to `recipient_id` (or PP_RECIPIENT_ANY). `now_ms` 0 = now. A fresh nonce unless `nonce` is
 * given (NULL). */
int pp_reqsig_sign(const pp_signer *s, const char *method, const char *target, const void *body, size_t body_len,
                   const char *recipient_id, int64_t now_ms, const char *nonce, char *out, size_t cap);

/* Strictly parse a header value: exact field order and formats, nothing extra. */
int pp_reqsig_parse(const char *header, pp_reqsig *out);

/* The exact text a request signature covers. The length, or -1 if it doesn't fit. */
int pp_reqsig_canonical(char *out, size_t cap, const char *method, const char *target, const void *body, size_t body_len,
                        int64_t ts, const char *nonce, const char *recipient);

/* Nonces remembered for ten minutes, so a request can't be played twice. Thread-safe. */
typedef struct pp_replay pp_replay;
pp_replay *pp_replay_new(size_t capacity); /* a power of two >= 8; 0 = 65536 */
void pp_replay_free(pp_replay *r);

typedef enum {
    PP_AUTHN_OK = 0,
    PP_AUTHN_REJECT = 1,   /* not authenticated: answer as if the path did not exist */
    PP_AUTHN_SKEW = 2,     /* authenticated, but the clock is off by more than five minutes */
    PP_AUTHN_REPLAYED = 3, /* authenticated, but this request was seen already */
    PP_AUTHN_BUSY = 4      /* authenticated, but the nonce memory is full */
} pp_authn;

/* Hand back the sender's *current* signing key, if `sender_id` is someone known and `kid` is that key: 1, else 0. */
typedef int (*pp_key_lookup_fn)(void *user, const char *sender_id, const char *kid, unsigned char sign_pub[32]);

/* Is the request from who it says, and for `my_id`? Parse; sender and key known; signature; clock; replay, stopping at the
 * first failure. Everything up to the signature is REJECT. `replay` NULL = not checked. `out` may be NULL. */
pp_authn pp_reqsig_authenticate(const char *header, const char *method, const char *target, const void *body, size_t body_len,
                                const char *my_id, pp_key_lookup_fn lookup, void *user, pp_replay *replay, int64_t now_ms,
                                pp_reqsig *out);

/* Only the clock and the replay memory, for a request already authenticated by someone trusted (a Levee hands over what it
 * checked): `ts` is checked against `now_ms` (0 = now). */
pp_authn pp_reqsig_fresh(const pp_reqsig *r, pp_replay *replay, int64_t now_ms);

/* ------------------------------------------------------------------ receipts (spec/02) */

#define PP_RECEIPT_MAX 320

typedef enum {
    PP_RECEIPT_OK = 0,
    PP_RECEIPT_MISSING,   /* none at all */
    PP_RECEIPT_WRONG_KEY, /* another id, or not the key we hold */
    PP_RECEIPT_BAD        /* malformed, or not over this request, status and body */
} pp_receipt_check;

/* X-Puddle-Receipt for the answer to the request with `nonce`: `body_hash_hex` is the SHA-256 of the answer as sent. */
int pp_receipt_sign(const pp_signer *s, const char *nonce, int status, const char *body_hash_hex, char *out, size_t cap);
pp_receipt_check pp_receipt_verify(const char *header, const char *peer_id, const unsigned char peer_pub[32], const char *nonce,
                                   int status, const char *body_hash_hex);

/* ------------------------------------------------------------------ custody receipts (spec/06) */

#define PP_CUSTODY_MAX 320

/* X-Puddle-Custody: a Levee (`s`) took the request with `nonce` and body hash for the Puddle `for_id`. */
int pp_custody_sign(const pp_signer *s, const char *for_id, const char *nonce, const char *body_hash_hex, char *out, size_t cap);
/* Did the Levee `levee_id`, whose key is `levee_pub`, take it for `for_id`? */
pp_receipt_check pp_custody_verify(const char *header, const char *for_id, const char *levee_id, const unsigned char levee_pub[32],
                                   const char *nonce, const char *body_hash_hex);

/* "When the Levee gives up" (spec/06): one item's `sig` in POST /stream/v1/undelivered, base64 of the Ed25519 signature
 * by the Levee (`s`) over the custody text under the label puddle-undelivered-v1. */
int pp_undelivered_sign(const pp_signer *s, const char *for_id, const char *nonce, const char *body_hash_hex, char *out, size_t cap);
/* Did the Levee `levee_id`, whose key is `levee_pub`, give up on that request for `for_id`? MISSING for an empty `sig`,
 * WRONG_KEY when the key isn't that Levee's. */
pp_receipt_check pp_undelivered_verify(const char *sig_b64, const char *for_id, const char *levee_id, const unsigned char levee_pub[32],
                                       const char *nonce, const char *body_hash_hex);

/* ------------------------------------------------------------------ sealing (spec/09) */

#define PP_SEAL_KEY_LEN 32
#define PP_SEAL_ENC_LEN 32
#define PP_SEAL_TAG_LEN 16
#define PP_SEAL_RECORD 65536

typedef struct {
    unsigned char key[32];
    unsigned char base_nonce[12];
    unsigned char exporter[32];
    uint64_t seq;
} pp_hpke;

/* RFC 9180 DeriveKeyPair, X25519. */
int pp_x25519_derive(const void *ikm, size_t ikm_len, unsigned char sk[32], unsigned char pk[32]);
int pp_x25519_public(const unsigned char sk[32], unsigned char pk[32]);

/* HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305. */
int pp_hpke_sender(const unsigned char pk_r[32], const void *info, size_t info_len, unsigned char enc[32], pp_hpke *ctx);
int pp_hpke_sender_with(const unsigned char sk_e[32], const unsigned char pk_r[32], const void *info, size_t info_len,
                        unsigned char enc[32], pp_hpke *ctx);
int pp_hpke_receiver(const unsigned char enc[32], const unsigned char sk_r[32], const void *info, size_t info_len, pp_hpke *ctx);
int pp_hpke_seal(pp_hpke *ctx, const void *aad, size_t aad_len, const void *pt, size_t len, unsigned char *out);
int pp_hpke_open(pp_hpke *ctx, const void *aad, size_t aad_len, const unsigned char *ct, size_t len, unsigned char *out);
int pp_hpke_export(const pp_hpke *ctx, const void *label, size_t label_len, unsigned char *out, size_t out_len);

/* Answers: records under the key exported as "puddle-answer-v1". */
int pp_seal_answer_key(const pp_hpke *ctx, unsigned char key[32]);
size_t pp_seal_answer_len(size_t plain_len);
size_t pp_seal_plain_len(size_t sealed_len);
int pp_seal_record(const unsigned char key[32], uint64_t index, int status, int last, const void *pt, size_t len, unsigned char *out);
int pp_open_record(const unsigned char key[32], uint64_t index, int status, int last, const unsigned char *ct, size_t len,
                   unsigned char *out);
int pp_seal_answer(const unsigned char key[32], int status, const void *pt, size_t len, unsigned char *out);
int pp_open_answer(const unsigned char key[32], int status, const unsigned char *ct, size_t len, unsigned char *out, size_t *out_len);

/* The info and aad of a sealed request. The length, or 0 if it doesn't fit. */
size_t pp_seal_info(const char *sender_id, const char *recipient_id, const char *nonce, char *out, size_t cap);
size_t pp_seal_aad(const char *method, const char *target, char *out, size_t cap);

/* A sealed, signed request (spec/09): the body sealed to `seal_pub`, the signature over the sealed bytes. */
typedef struct {
    char signature[PP_REQSIG_MAX]; /* X-Puddle-Signature */
    char seal[160];                /* X-Puddle-Seal */
    char nonce[32];
    unsigned char *body;           /* the sealed body, malloc'd; NULL when there was none */
    size_t body_len;
    unsigned char answer_key[32];
} pp_sealed_request;

int pp_seal_request(const pp_signer *s, const char *method, const char *target, const void *body, size_t body_len,
                    const char *recipient_id, const unsigned char seal_pub[32], int64_t now_ms, pp_sealed_request *out);
void pp_sealed_request_free(pp_sealed_request *r);

/* Parse X-Puddle-Seal. */
int pp_seal_header_parse(const char *header, char kid[65], unsigned char enc[PP_SEAL_ENC_LEN]);

/* Open a sealed request's body (the recipient's side): `sk` is the recipient's sealing key; `out` gets body_len - TAG bytes.
 * The answer key in `answer_key`. `body`/`body_len` may be empty (a GET): then only the answer key. */
int pp_open_request(const char *seal_header, const unsigned char sk[32], const char *sender_id, const char *recipient_id,
                    const char *nonce, const char *method, const char *target, const unsigned char *body, size_t body_len,
                    unsigned char *out, unsigned char answer_key[32]);

/* ------------------------------------------------------------------ pieces (spec/10 and spec/06): a file under its own key */

#define PP_PIECE_HASHES ((uint64_t)1 << 40)
/* Seal or open one piece (`piece` a chunk number, or PP_PIECE_HASHES) under a file key, as records of PP_SEAL_RECORD, record k
 * at index piece*64+k, with `status` in the aad. Sealed size: pp_seal_answer_len(len). */
int pp_seal_piece(const unsigned char key[32], uint64_t piece, int status, const void *pt, size_t len, unsigned char *out);
int pp_open_piece(const unsigned char key[32], uint64_t piece, int status, const unsigned char *ct, size_t len, unsigned char *out,
                  size_t *out_len);

#ifdef __cplusplus
}
#endif
#endif
