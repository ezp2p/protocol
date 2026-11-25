#ifndef PP_JSON_H
#define PP_JSON_H

/* A strict JSON reader, enough to check key chains: the library's own, internal. */

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *p;
    size_t len;
} pp_span;

int pp_json_valid_object(const char *json, size_t len);
/* 0 found, 1 not found, -1 malformed or the key appears twice */
int pp_json_member(const char *json, size_t len, const char *key, pp_span *val);
int pp_json_array_next(pp_span array, size_t *cursor, pp_span *item);
int pp_json_int64(pp_span v, int64_t *out);
int pp_json_string(pp_span v, char *out, size_t cap);

#endif
