#include <string.h>
#include <stdarg.h>
#include <openssl/sha.h>
#include <libdank/utils/hex.h>
#include <libdank/objects/logctx.h>
#include <libdank/utils/memlimit.h>
#include "misc.h"

unsigned char *convert_ascii_hash(const char *ascii_hash, size_t len) {
  unsigned char *result; 

  if(strlen(ascii_hash) < 2 * len) {
    nag("Ascii hash too short\n");
    return NULL;
  }
  
  result = Malloc("bin_hash", len);
  if(!result) {
    nag("Can't alloc memory for decoded hash\n");
    return NULL;
  }

  if(!hextoascii(ascii_hash, result, EOF, len)) {
    nag("Error converting hex string\n");
    Free(result);
    return NULL;
  }

  return result;
}

void *hex2bin(const char *asciihex, size_t *len) {
  void *result; 
  
  *len = strlen(asciihex);
  
  if(*len % 2 || !*len) {
    bitch("Ascii hex string has invalid %zu characters\n",*len);
    return NULL;
  }
  
  *len /= 2;

  result = Malloc("bindata", *len);
  if(!result) {
    return NULL;
  }

  if(!hextoascii(asciihex, result, EOF, *len)) {
    nag("Error converting hex string\n");
    Free(result);
    return NULL;
  }

  return result;
}

// Helper function to convert a password into a password hash.
unsigned char *gen_pw_hash(const char *username, const char *password) {
  ustring us = USTRING_INITIALIZER;
  unsigned char *result = NULL;
  const char *pa_salt = "<P$db=\\!Y&!oop@LFZ{x(#Tn!309oukRn<9'6oK\\[Sqc:&R5-u]P'T_\"r>R7OzD_r>R7OzD";

  if(printUString(&us, "%s%s%s", pa_salt, username, password) < 0) {
    nag("Concatenation of input data failed\n");
    goto cleanup;
  }

  result = Malloc("pw_hash", SHA_DIGEST_LENGTH);
  if(!result) {
    nag("No memory for pw_hash\n");
    goto cleanup;
  }

  SHA1((const unsigned char *)us.string, us.current, result);
  
 cleanup:
  reset_ustring(&us);
  return result;
}

// Use hexnag macro. Similar to nag(), but preceed output with len bytes in hex from buffer.
void hexnag_internal(const char *funcname, const void *buffer, size_t len, const char *fmt, ...) {
  va_list ap;
  ustring us = USTRING_INITIALIZER;
  size_t i;

  for(i = 0; i < len; ++i) {
    unsigned char c = ((const unsigned char*)buffer)[i];
    if(printUString(&us, "%02x ", c) < 0) {
      nag("Error while printing to ustring\n");
      goto cleanup;
    }
  }
  
  if(printUString(&us, "\t") < 0) {
    nag("Error while printing to ustring\n");
    goto cleanup;
  }

  va_start(ap, fmt);

  if(vprintUString(&us, fmt, ap) < 0) {
    nag("Error while printing to ustring\n");
    goto cleanup;
  }

  va_end(ap);

  flog("%s] %s\n", funcname, us.string);

 cleanup:
  reset_ustring(&us);
}
