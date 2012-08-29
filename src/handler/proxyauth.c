// Code to implement Digest Proxy Authentication

#include <ctype.h>
#include <string.h>
#include <netinet/in.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <libdank/objects/objustring.h>
#include <libdank/objects/logctx.h>
#include <libdank/objects/lexers.h>
#include <libdank/utils/string.h>
#include <libdank/utils/memlimit.h>
#include <util/base64.h>
#include <util/misc.h>
#include "param.h"
#include "vid_nc_map.h"
#include "handlerconf.h"
#include "handler_common.h"
#include "proxyauth.h"

// The realm we use for proxy authentication. The browser will show this
// to the client, and it is also used in password hash calculations (the
// HA1 hash).
#define PROXY_AUTH_REALM	"Secure Web Browsing"

#define NONCE_LIFETIME		3600

static void
bintolchex(const void *voidbuf,char *hex,int sep,size_t len);

// Generate a header to go along with the 407 response requesting auth
// information from the client.
char *gen_authenticate_hdr(uint32_t nip, const unsigned char *secret, unsigned int vid, int is_stale) {
  ustring us = USTRING_INITIALIZER;
  char *ret = NULL;
  char *opaque = "01"; // currently unused
  char *stale = "";
  uint32_t ts, tsn;
  SHA_CTX shactx;
  unsigned char sha1[SHA_DIGEST_LENGTH];
  char sha1_hex[2 * SHA_DIGEST_LENGTH + 1];
  uint32_t vidn;

  // Calculate a hash for the nonce
  ts = (uint32_t)time(0);
  tsn = htonl(ts);
  vidn = htonl(vid);
  SHA_Init(&shactx);
  SHA_Update(&shactx, &tsn, sizeof(uint32_t));
  SHA_Update(&shactx, &nip, sizeof(uint32_t));
  SHA_Update(&shactx, &vidn, sizeof(uint32_t));
  SHA_Update(&shactx, secret, strlen((const char*)secret));
  SHA_Final(sha1, &shactx);
  bintolchex(sha1, sha1_hex, EOF, SHA_DIGEST_LENGTH);

  if(is_stale) {
    stale = ", stale=true";
  }

  if(printUString(&us,
		  "Proxy-Authenticate: Digest realm=\"" PROXY_AUTH_REALM "\", "
		  "qop=\"auth\", "
		  "nonce=\"%u-%u-%u-%s\", "
		  "opaque=\"%s\""
		  "%s",
		  (unsigned int)ts, (unsigned int)nip, vid, sha1_hex, opaque, stale
		  ) < 0) {
    goto cleanup;
  }

  ret = Strdup(us.string);

 cleanup:
  reset_ustring(&us);
  return ret;
}

// Checks whether the nonce returned from the client is valid
static int
check_nonce(const char *nonce, uint32_t nip_ref, const unsigned char *secret, unsigned int *vid, int *stale) {
  uint32_t ts, tsn;
  uint32_t nip;
  SHA_CTX shactx;
  unsigned char sha1[SHA_DIGEST_LENGTH];
  char sha1_hex[2 * SHA_DIGEST_LENGTH + 1];
  long delta;
  unsigned int avid;
  uint32_t vidn;

  *stale = 0;
  *vid = 0;

  if(lex_u32(&nonce, &ts)) {
    nag("Error lexing timestamp\n");
    return 0;
  }
  if(*nonce != '-') {
    nag("Expected delimiter\n");
    return 0;
  }
  nonce++;
  if(lex_u32(&nonce, &nip)) {
    nag("Error lexing IP\n");
    return 0;
  }
  if(*nonce != '-') {
    nag("Expected delimiter\n");
    return 0;
  }
  nonce++;
  if(lex_u32(&nonce, &avid)) {
    nag("Error lexing vid\n");
    return 0;
  }
  if(*nonce != '-') {
    nag("Expected delimiter\n");
    return 0;
  }
  nonce++;

  // Check ts
  delta = (long)time(0) - (long)ts;
  if(delta > NONCE_LIFETIME) {
    // The nonce is to old, send a new one to the clien
    nag("Nonce is %ld seconds old, marking as stale\n", delta);
    *stale = -1;
    return 0;
  }

  // Check nip
  if(nip_ref != nip) {
    nag("Invalid IP\n");
    return 0;
  }

  tsn = htonl(ts);
  vidn = htonl(avid);
  SHA_Init(&shactx);
  SHA_Update(&shactx, &tsn, sizeof(uint32_t));
  SHA_Update(&shactx, &nip, sizeof(uint32_t));
  SHA_Update(&shactx, &vidn, sizeof(uint32_t));
  SHA_Update(&shactx, secret, strlen((const char*)secret));
  SHA_Final(sha1, &shactx);
  bintolchex(sha1, sha1_hex, EOF, SHA_DIGEST_LENGTH);

  if(strcmp(sha1_hex, nonce)) {
    nag("Hash in nonce is invalid\n");
    return 0;
  }
  
  *vid = avid;

  nag("Nonce is valid at %lds\n",delta);
  return -1;
}

// This comes from libdank (and needs to go back there at some point). It's
// modified to return lower case hex values as required by RFC 2617.
static void
bintolchex(const void *voidbuf,char *hex,int sep,size_t len){
  const unsigned char *buf = voidbuf;
  int i = 0;

  while(len > 1){
    if(sep != EOF){
      i += sprintf(hex + i,"%02x%c",*buf,sep);
    }else{
      i += sprintf(hex + i,"%02x",*buf);
    }
    ++buf;
    --len;
  }
  if(len == 1){
    i += sprintf(hex + i,"%02x",*buf);
    ++buf;
    --len;
  }
  hex[i] = '\0';
}

static void
remove_ws_quotes(char **str) {
  char *cur;
  while(**str && isspace(**str)) {
    (*str)++;
  }
  if(**str == '\"') {
    (*str)++;
  }
  cur = *str;
  while(*cur) {
    cur++;
  }
  if(cur > *str) {
    cur--;
    while(cur > *str && isspace(*cur)) {
      *cur = '\0';
      cur--;
    }
    if(cur > *str && *cur == '\"') {
      *cur = '\0';
      cur--;
    }
  }
}

// Calculates HA1 as defined by RFC 2617 (with algorithm=MD5)
/*
static void
calculate_ha1(unsigned char *dst, const char *username, const char *realm, const char *password) {
  MD5_CTX md5ctx;
  MD5_Init(&md5ctx);
  MD5_Update(&md5ctx, username, strlen(username));
  MD5_Update(&md5ctx, ":", 1);
  MD5_Update(&md5ctx, realm, strlen(realm));
  MD5_Update(&md5ctx, ":", 1);
  MD5_Update(&md5ctx, password, strlen(password));
  MD5_Final(dst, &md5ctx);
}
*/

// Calculates HA2 as defined by RFC 2617 (with qop=auth)
static void
calculate_ha2(unsigned char *dst, const char *method, const char *digesturi) {
  MD5_CTX md5ctx;
  MD5_Init(&md5ctx);
  MD5_Update(&md5ctx, method, strlen(method));
  MD5_Update(&md5ctx, ":", 1);
  MD5_Update(&md5ctx, digesturi, strlen(digesturi));
  MD5_Final(dst, &md5ctx);
}

// Calculates response as defined by RFC 2617
static void
calculate_response(unsigned char *dst,
		   const char *ha1hex,
		   const char *method, const char *digesturi,
		   const char *nonce, const char *nc, const char *cnonce, const char *qop) {
  unsigned char ha2[MD5_DIGEST_LENGTH];
  char ha2hex[2 * MD5_DIGEST_LENGTH + 1];

  MD5_CTX md5ctx;

  calculate_ha2(ha2, method, digesturi);
  bintolchex(ha2, ha2hex, EOF, MD5_DIGEST_LENGTH);

  MD5_Init(&md5ctx);
  MD5_Update(&md5ctx, ha1hex, strlen(ha1hex));
  MD5_Update(&md5ctx, ":", 1);
  MD5_Update(&md5ctx, nonce, strlen(nonce));
  MD5_Update(&md5ctx, ":", 1);
  MD5_Update(&md5ctx, nc, strlen(nc));
  MD5_Update(&md5ctx, ":", 1);
  MD5_Update(&md5ctx, cnonce, strlen(cnonce));
  MD5_Update(&md5ctx, ":", 1);
  MD5_Update(&md5ctx, qop, strlen(qop));
  MD5_Update(&md5ctx, ":", 1);
  MD5_Update(&md5ctx, ha2hex, 2 * MD5_DIGEST_LENGTH);
  MD5_Final(dst, &md5ctx);
}

static int
check_basic_auth(char *creds, unsigned int *uid) {
  int ret = 0;
  char *creds_dec = NULL;
  char *user, *pass;
  const unsigned char *pw_hash_ref;
  unsigned char *pw_hash = NULL;

  creds_dec = base64_decode((unsigned char*)creds, strlen(creds));
  if(!creds_dec) {
    goto cleanup;
  }

  pass = creds_dec;
  user = strsep(&pass, ":");

  if(!user || !pass) {
    nag("Tokenizing credentials failed\n");
    goto cleanup;
  }

  nag("user: [%s], pass: [%s]\n", user, pass);

  *uid = ec_get_uid_by_name(ec, user);
  if(!*uid) {
    nag("Unknown username, proxy auth failed\n");
    goto cleanup;
  }

  // Now find the password hash based on the uid
  pw_hash_ref = ec_get_pwhash_by_uid(ec, *uid);
  if(!pw_hash_ref) {
    nag("No password for uid %u, browser plugin auth failed\n", *uid);
    goto cleanup;
  }

  pw_hash = gen_pw_hash(user, pass);
  if(memcmp(pw_hash, pw_hash_ref, SHA_DIGEST_LENGTH)) {
    nag("Password is incorrect\n");
    goto cleanup;
  }

  ret = -1;
 cleanup:
  Free(pw_hash);
  Free(creds_dec);
  return ret;
}

int check_authorization_header(const char *authhdr, const char *method, uint32_t nip,
			       const unsigned char *secret, unsigned int *uid, 
			       unsigned int *vid, int *stale) {
  int ret = 0;
  ParamNodeType *plist = NULL;
  char *hdr = NULL;
  char *scheme, *digresp;
  char *username, *realm, *nonce, *uri, *qop, *nc, *cnonce, *response, *opaque; 
  unsigned char response_ref[MD5_DIGEST_LENGTH];
  char response_ref_hex[2 * MD5_DIGEST_LENGTH + 1];
  const char *password_ha1;
  uint32_t nnc;
  unsigned int last_nc;

  *stale = 0;
  *vid = 0;

  hdr = Strdup(authhdr);
  if(!hdr) {
    goto cleanup;
  }

  nag("method [%s], authhdr [%s]\n", method, authhdr);

  digresp = hdr;
  scheme = strsep(&digresp, " ");
  if(!scheme || !digresp) {
    nag("Tokenization failed\n");
    goto cleanup;
  }

  if(strcasecmp(scheme, "Basic") == 0) {
    nag("Client sent Basic auth data\n");
    if(check_basic_auth(digresp, uid)) {
      nag("Valid Basic auth data\n");
      ret = -1;
      goto cleanup;
    } else {
      nag("Incorrect Basic auth data\n");
      goto cleanup;
    }
  } else if(strcasecmp(scheme, "Digest")) {
    nag("Unsupported authentication scheme\n");
    goto cleanup;
  }

  plist = parse_params_quoteaware(digresp, ",");

#define GET_FIELD(name) \
  name = get_param_value(plist, #name, 1); \
  if(!name) { \
    nag(#name " is missing in header\n"); \
    goto cleanup; \
  } \
  remove_ws_quotes(&name); \
  nag("Extracted " #name ": [%s]\n", name);

  GET_FIELD(username)
  GET_FIELD(realm)
  GET_FIELD(nonce)
  GET_FIELD(uri)
  GET_FIELD(qop)
  GET_FIELD(nc)
  GET_FIELD(cnonce)
  GET_FIELD(response)
  GET_FIELD(opaque)

#undef GET_FIELD

  if(strcmp(realm, PROXY_AUTH_REALM)) {
    nag("Wrong realm\n");
    goto cleanup;
  }

  *uid = ec_get_uid_by_name(ec, username);
  if(!*uid) {
    nag("Unknown user\n");
    goto cleanup;
  }

  if(!check_nonce(nonce, nip, secret, vid, stale)) {
    nag("Nonce is invalid\n");
    goto cleanup;
  }
  
  nag("Using vid %u for client\n", *vid);

  password_ha1 = ec_get_pwha1_by_uid(ec, *uid);
  if(!password_ha1) {
    nag("No HA1 hash available for uid %u\n", *uid);
    goto cleanup;
  }

  calculate_response(response_ref,
		     password_ha1,
		     method, uri,
		     nonce, nc, cnonce, qop);
  bintolchex(response_ref, response_ref_hex, EOF, MD5_DIGEST_LENGTH);  
  if(strcasecmp(response_ref_hex, response)) {
    nag("Digest response did not match [%s] != [%s]\n", response_ref_hex, response);
    goto cleanup;
  }

  // xxx check nc against uid, needs more work
  if(lex_u32_ashex((const char **)&nc, &nnc)) {
    nag("Error lexing nc\n");
    goto cleanup;
  }
  last_nc = get_nc(*vid);
  set_nc(*vid, nnc);
  nag("Current nc: %u, last nc: %u\n", (unsigned int)nnc, last_nc);
  if(last_nc >= nnc) {
    nag("Nonce count went down... replay attack?\n");
    bstats.proxyauth_nonce_down++;
    // Unfortunately, WW shuffles our nonces occasionally, so we'll remove this
    // check until we figured out how to solve this
    // *stale = 1;
    // goto cleanup;
  }
  if(nnc >= last_nc + get_proxyauth_nonce_diff()) {
    nag("Nonce count significantly higher than last reported one, forcing client to start over\n");
    *stale = 1;
    goto cleanup;
  }
  if(nnc > 0xf0000000) {
    nag("Large nonce count, forcing client to start over\n");
    *stale = 1;
    goto cleanup;
  }

  ret = -1;
 cleanup:
  Free(hdr);
  delete_param_list(plist);
  if(!ret) {
    // If we force a new nonce, make sure that the nc counter is reset
    (void)get_nc(*vid);
    set_nc(*vid, 0);
  }
  return ret;
}
