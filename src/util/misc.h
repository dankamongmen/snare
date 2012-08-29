#ifndef MISC_H
#define MISC_H

#include <openssl/sha.h>
#include <openssl/md4.h>

#ifdef __cplusplus
extern "C" {
#endif

#define convert_ascii_sha1(h) convert_ascii_hash((h), SHA_DIGEST_LENGTH)
#define convert_ascii_md4(h) convert_ascii_hash((h), MD4_DIGEST_LENGTH)

unsigned char *convert_ascii_hash(const char *ascii_hash, size_t len);
void *hex2bin(const char *asciihex, size_t *len);
unsigned char *gen_pw_hash(const char *username, const char *password);
void hexnag_internal(const char *funcname, const void *buffer, size_t len, const char *fmt, ...)
  __attribute__ ((format (printf, 4, 5)));

#define hexnag(buf, len, fmt, ...) \
  hexnag_internal(__func__, buf, len, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif
