#include <string.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <libdank/utils/memlimit.h>
#include <libdank/utils/hex.h>
#include <libdank/objects/objustring.h>
#include <libdank/objects/lexers.h>
#include <libdank/objects/logctx.h>
#include "util/base64.h"
#include "pluginauth.h"

static char*
convert_token(const char *token) {
  size_t len;
  char *result = NULL;
  ustring us = USTRING_INITIALIZER;
  
  len = strlen(token);
  if(!len || len % 4 != 0) {
    nag("Token has invalid length\n");
    goto cleanup;
  }

  // The conversion function expects a \n at the end
  if(printUString(&us, "%s\n", token) < 0) {
    nag("Error formatting input string\n");
    goto cleanup;
  }
  
  result = base64_decode((unsigned char*)us.string, us.current);
  if(!result) {
    nag("Conversion failed\n");
    goto cleanup;
  }

 cleanup:
  reset_ustring(&us);
  return result;
}

// Verifies if the auth data from the browser plugin is correct. Returns -1 if
// the data checks out. Pw_hash is a buffer of size SHA_DIGEST_LENGTH.
int check_plugin_auth(const char *version, const char *user, const char *timestamp, const char *token,
		      time_t now, long _auth_time_window, const char *url, const unsigned char *pw_hash) {
  int ret = 0;
  uint16_t ver;
  int64_t ts;
  ustring us = USTRING_INITIALIZER;
  long delta;
  char *bin_token = NULL;
  char hmac[SHA_DIGEST_LENGTH];

  if(lex_u16(&version, &ver)) {
    nag("Lexing version failed\n");
    goto cleanup;
  }

  if(ver != 1) {
    nag("Unsupported version: %u\n", ver);
    goto cleanup;
  }
  
  if(lex_s64(&timestamp, &ts)) {
    nag("Lexing timestamp failed\n");
    goto cleanup;
  }

  delta = (long)now - (long)ts;
  if(labs(delta) > _auth_time_window) {
    nag("Auth data expired\n");
    goto cleanup;
  }

  bin_token = convert_token(token);
  if(!bin_token) {
    nag("Invalid token\n");
    goto cleanup;
  }

  if(printUString(&us, "%s%s%jd%u", url, user, (intmax_t)ts, (unsigned int)ver) < 0) {
    nag("Concatenation of input data failed\n");
    goto cleanup;
  }

  HMAC(EVP_sha1(),
       (const void*)pw_hash, SHA_DIGEST_LENGTH,	// The password hash is also a SHA1 hash
       (unsigned char*)us.string, us.current,
       (unsigned char*)hmac, 0);
  if(memcmp(bin_token, hmac, SHA_DIGEST_LENGTH)) {
    nag("HMAC doesn't match\n");
    goto cleanup;
  }

  ret = -1;
 cleanup:
  Free(bin_token);
  reset_ustring(&us);
  return ret;
}
