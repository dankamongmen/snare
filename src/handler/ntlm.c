#include <libdank/objects/objustring.h>
#include <libdank/utils/memlimit.h>
#include <libdank/objects/logctx.h>
#include <libdank/ersatz/compat.h>
#include <libdank/utils/string.h>
#include <libdank/utils/hex.h>
#include <openssl/hmac.h>
#include <openssl/md4.h>
#include "snare/icap/transmogrify.h"
#include "handler/handler_common.h"
#include "util/url_escape.h"
#include "handler/mobclt.h"
#include "handler/cookie.h"
#include "handler/ntlmv2.h"
#include "handler/ntlm.h"
#include "util/base64.h"

// This is the target information block we send in our type 2 message. For
// NTLMv2 authentication with password verification, we expect to see the
// same block in the client's type 3 response.
#define NTLM_TARGET_INFO \
  "\x01\x00\x10\x00"	/* target informatiom, server name with length 0x10 */ \
  "\x57\x00\x45\x00"	/* "WE" */ \
  "\x42\x00\x50\x00"	/* "BP" */ \
  "\x52\x00\x4f\x00"	/* "RO" */ \
  "\x58\x00\x59\x00"	/* "XY" */ \
  "\x00\x00\x00\x00"	/* terminator subblock */

int ntlm_check_if_type1(const void *ntlmbuf, size_t ntlmlen) {
  if(ntlmlen < 32) {
    // too short
    return 0;
  }
  if(memcmp(ntlmbuf, "NTLMSSP\0\x01", 9)) {
    return 0;
  }
  // type 1 message
  return -1;
}

// Returns pointer to challenge (needs to be at least 8 bytes; only first 8 bytes
// are used), returns null on error.
// Since there is no state, we use the client IP to generate a challenge. This should
// be improved with the WW connection id (once available) and some sort of timestamp.
static void*
ntlm_gen_challenge(uint32_t nip) {
  const char *salt = "H%^ty67yvyd7GCKhjL:;lkLjBGHgfsk;hSuyfgh>:l;dnvXZS;Dbf7gD78UY#78G#hjbD78g#jk :)";
  SHA_CTX shactx;
  void *hash = Malloc("challenge", SHA_DIGEST_LENGTH);
  if(!hash) {
    return NULL;
  }
  SHA_Init(&shactx);
  SHA_Update(&shactx, salt, strlen(salt));
  SHA_Update(&shactx, &nip, sizeof(uint32_t));
  SHA_Final(hash, &shactx);
  return hash;
}

// Challenge has to be a pointer to an 8 byte array (or NULL for default challenge)
char *ntlm_gen_type2(const void *challenge) {
  const char type2_template[] =
    "NTLM"
    "SSP\0"
    "\x02\x00\x00\x00"	//  8 - type 2
    "\x00\x00\x00\x00"	// 12 - target name, len/allox both zero -- we don't provide this
    "\xff\x00\x00\x00"	// 16 - target name, offset 0xff (fill in) -- point past last byte, zero buffer
    "\x01\x02\x82\x00"	// 20 - flags
    "aaaa"		// 24 - challenge (fill in)
    "bbbb"		// 28
    "\x00\x00\x00\x00"	// 32 - context
    "\x00\x00\x00\x00"	// 36
    "\xff\x00\xff\x00"	// 40 - target information, len/alloc 0xff (fill in)
    "\x30\x00\x00\x00"  // 44 - target information, offset 0x30 (48) -- data follows after static data (just after this)
    NTLM_TARGET_INFO;	// ?? - offset for index 44
    
  char *type2, *b64type2;

  type2 = Memdup("type2", type2_template, sizeof(type2_template));
  if(!type2) {
    return NULL;
  }
  
  // fill in challenge at index 24 (8 bytes)
  if(challenge) {
    memcpy(type2 + 24, challenge, 8);
  }

  // fill in target info at index 40 and index 42 (1 byte is sufficient here)
  type2[40] = type2[42] = (unsigned char)(sizeof(NTLM_TARGET_INFO) - 1); // subtract null byte introduced by string literal

  // fill in target name offset at index 16
  type2[16] = (unsigned char)(sizeof(type2_template) - 1);

  b64type2 = base64_bin_encode(type2, sizeof(type2_template) - 1);
  Free(type2);
  return b64type2;
}

static uint8_t
odd_parity(uint8_t b) {
  int parity = (((b >> 7) ^ (b >> 6) ^ (b >> 5) ^
		 (b >> 4) ^ (b >> 3) ^ (b >> 2) ^
		 (b >> 1)) & 0x01) == 0;
  if(parity) {
    return b | 0x01;
  } else {
    return b & 0xfe;
  }
}

void des_parity_adjust(const unsigned char *key7, DES_cblock pkey) {
  pkey[0] = odd_parity(key7[0]);
  pkey[1] = odd_parity(key7[0] << 7 | (key7[1] & 0xff) >> 1);
  pkey[2] = odd_parity(key7[1] << 6 | (key7[2] & 0xff) >> 2);
  pkey[3] = odd_parity(key7[2] << 5 | (key7[3] & 0xff) >> 3);
  pkey[4] = odd_parity(key7[3] << 4 | (key7[4] & 0xff) >> 4);
  pkey[5] = odd_parity(key7[4] << 3 | (key7[5] & 0xff) >> 5);
  pkey[6] = odd_parity(key7[5] << 2 | (key7[6] & 0xff) >> 6);
  pkey[7] = odd_parity(key7[6] << 1);
}

// Computes the correct NTLM response for the given NTLM password hash and
// challenge data. Response is pointer to 24 bytes of memory.
// Returns -1 on error, 0 if success.
int ntlm_response(const void *pw_md4, const void *challenge, unsigned char *response) {
  int ret = -1;
  unsigned char *padpw;
  void *ntlmresp_ref = NULL;
  DES_cblock key1, key2, key3;
  DES_key_schedule sched1, sched2, sched3;
  DES_cblock in, out;

  padpw = Malloc("padpw", 21);
  if(!padpw) {
    goto cleanup;
  }
  memset(padpw,0,21);
  (void)memcpy(padpw, pw_md4, MD4_DIGEST_LENGTH);
  
  // We now have 3 7-byte keys -- parity adjust each of them
  des_parity_adjust(padpw, key1);
  des_parity_adjust(padpw + 7, key2);
  des_parity_adjust(padpw + 14, key3);

  ntlmresp_ref = Malloc("ntlmresp_ref", 24);
  if(!ntlmresp_ref) {
    goto cleanup;
  }
  memset(ntlmresp_ref,0,24);

  des_set_key_unchecked(&key1, sched1);
  des_set_key_unchecked(&key2, sched2);
  des_set_key_unchecked(&key3, sched3);

  (void)memcpy(in, challenge, 8);
  DES_ecb_encrypt(&in, &out, &sched1, DES_ENCRYPT);
  (void)memcpy(response, out, 8);
  DES_ecb_encrypt(&in, &out, &sched2, DES_ENCRYPT);
  (void)memcpy(response + 8, out, 8);
  DES_ecb_encrypt(&in, &out, &sched3, DES_ENCRYPT);
  (void)memcpy(response + 16, out, 8);

  ret = 0;
 cleanup:
  Free(padpw);
  Free(ntlmresp_ref);
  return ret;
}

// Verifies that the NTLM response in the type 3 message pointed to by ntlmbuf
// is valud for the given password and the given client IP.
// Returns -1 on error, 1 if password invalid, 0 if success.
int ntlm_verify_password(const unsigned char *ntlmbuf, size_t ntlmlen, const void *pw_md4, uint32_t nip) {
  int ret = -1;
  void *challenge = NULL;

  // Since we don't keep state, the challenge is based on the client's IP
  // address, which is constant during multiple requests.
  challenge = ntlm_gen_challenge(nip);
  if(!challenge) {
    goto cleanup;
  }

  ret = ntlm_verify_password_internal(ntlmbuf, ntlmlen, pw_md4, challenge,
				      NTLM_TARGET_INFO, sizeof(NTLM_TARGET_INFO) - 1);
 cleanup:
  return ret;
}

// Same as above, but takes a raw challenge (so that we can more easily run test cases)
int ntlm_verify_password_internal(const unsigned char *ntlmbuf, size_t ntlmlen,
				  const void *pw_md4, const void *challenge, 
				  const void *target_info, size_t target_info_len) {
  int ret = -1;
  size_t nresp_len, nresp_alloc, nresp_off;
  unsigned char nresp_ref[24];
  void *ntlmv2hash = NULL;
  char *user = NULL;

  if(ntlmlen < 0x1c) { // make sure that we can at least access the nresp sec buffer
    goto cleanup;
  }

  nresp_len = read_le_16(ntlmbuf + 0x14);
  nresp_alloc = read_le_16(ntlmbuf + 0x16);
  nresp_off = read_le_16(ntlmbuf + 0x18);

  if(ntlmlen < nresp_off + nresp_len) {
    goto cleanup;
  }

  if(nresp_len != 24) {
    // Test NTLMv2 response
    size_t user_len, user_alloc, user_off;
    size_t domain_len, domain_alloc, domain_off;

    nag("NTLM response length is %zu, assuming NTLMv2,\n", nresp_len);

    if(ntlmlen < 44) { // make sure that we can access the user name sec buffer
      goto cleanup;
    }

    // Get the user name data
    user_len = read_le_16(ntlmbuf + 36);
    user_alloc = read_le_16(ntlmbuf + 38);
    user_off = read_le_16(ntlmbuf + 40);

    // Some sanity checks to make sure we stay in our buffer
    if(ntlmlen < user_off + user_len) {
      goto cleanup;
    }

    // Get domain data
    domain_len = read_le_16(ntlmbuf + 28);
    domain_alloc = read_le_16(ntlmbuf + 30);
    domain_off = read_le_16(ntlmbuf + 32);

    // Some sanity checks to make sure we stay in our buffer
    if(ntlmlen < domain_off + domain_len) {
      goto cleanup;
    }

    // Convert user to UTF-8
    user = utf16le_to_utf8((const char*)ntlmbuf + user_off, user_len);
    if(!user) {
      goto cleanup;
    }

    if(!target_info) {
      nag("Target information data missing\n");
      goto cleanup;
    }

    // Generate the NTLMv2 hash based on user name, target name, and NTLM hash
    ntlmv2hash = ntlmv2_gen_hash_t16(user, (const char *)ntlmbuf + domain_off, domain_len, pw_md4);
    if(!ntlmv2hash) {
      goto cleanup;
    }

    // Verify that the NTLMv2 response the client provided check out
    ret = ntlmv2_verify_password(ntlmbuf + nresp_off, nresp_len, challenge, ntlmv2hash,
				 target_info, target_info_len, time(0));
    if(ret) {
      nag("Invalid password or error during NTLMv2\n");
      goto cleanup;
    }
  } else {
    // Regular NTLM response
    // Calculate reference response
    if(ntlm_response(pw_md4, challenge, nresp_ref)) {
      nag("Generating NTLM response failed\n");
      goto cleanup;
    }
    
    // Compare client response with reference
    if(memcmp(nresp_ref, ntlmbuf + nresp_off, 24)) {
      nag("Invalid password\n");
      ret = 1;
      goto cleanup;
    }
  }

  ret = 0;
 cleanup:
  Free(ntlmv2hash);
  Free(user);
  return ret;
}

// Parses an NTLM type 3 message.
// Returns -1 on error and 0 on success.
int ntlm_decode_type3(const unsigned char *ntlmbuf, size_t ntlmlen, ntlm_type3_data *result) {
  int ret = -1;
  const unsigned char *buf = ntlmbuf;
  size_t domain_len, domain_alloc, domain_off;
  size_t user_len, user_alloc, user_off;
  size_t host_len, host_alloc, host_off;

  reset_type3_data(result);

  if(ntlmlen < 8 + 4 + 8 + 8 + 8 + 8 + 8) {
    nag("Message too short\n");
    goto cleanup;
  }

  if(strcmp((const char*)buf, "NTLMSSP")) {
    nag("NTLM message does not begin with \"NTLMSSP\"\n");
    goto cleanup;
  }
  buf += 8;

  if(*(const uint8_t*)buf != 3) {
    nag("Not a type 3 message\n");
    goto cleanup;
  }
  buf += 1;
  buf += 3; // skip 3 zero bytes
  
  // LAN manager response meta data
  buf += 8;

  // NT response meta data
  buf += 8;
  
  // Domain (target)
  domain_len = read_le_16(buf);
  buf += 2;
  domain_alloc = read_le_16(buf);
  buf += 2;
  domain_off = read_le_16(buf); // xxx fixme -- technically, this is a 4 byte value
  buf += 2;
  buf += 2;	// skip 2 zero bytes

  // User
  user_len = read_le_16(buf);
  buf += 2;
  user_alloc = read_le_16(buf);
  buf += 2;
  user_off = read_le_16(buf);
  buf += 2;
  buf += 2;	// skip 2 zero bytes

  // Host
  host_len = read_le_16(buf);
  buf += 2;
  host_alloc = read_le_16(buf);
  buf += 2;
  host_off = read_le_16(buf);
  buf += 2;
  buf += 2;	// skip 2 zero bytes

  // Some integrity checks
  if(domain_off + domain_len > ntlmlen) {
    goto cleanup;
  }
  if(user_off + user_len > ntlmlen) {
    goto cleanup;
  }
  if(host_off + host_len > ntlmlen) {
    goto cleanup;
  }

  result->domain = utf16le_to_utf8((const char*)ntlmbuf + domain_off, domain_len);
  if(!result->domain) {
    goto cleanup;
  }

  result->user = utf16le_to_utf8((const char*)ntlmbuf + user_off, user_len);
  if(!result->user) {
    goto cleanup;
  }

  result->host = utf16le_to_utf8((const char*)ntlmbuf + host_off, host_len);
  if(!result->host) {
    goto cleanup;
  }

  ret = 0;
 cleanup:
  if(ret) {
    free_type3_data(result);
  }
  return ret;
}

void free_type3_data(ntlm_type3_data *nd) {
  Free(nd->domain);
  Free(nd->user);
  Free(nd->host);
  reset_type3_data(nd);
}

void reset_type3_data(ntlm_type3_data *nd) {
  nd->domain = NULL;
  nd->user = NULL;
  nd->host = NULL;
}


// functions to send ntlm/http responses

int reqresp_ntlm_challenge(struct icap_state *is) {
  const char *response_body = "NTLM authentication requested"; // xxx
  ustring response_hdr = USTRING_INITIALIZER;
  int ret = -1;

  if(printUString(&response_hdr,
		  "HTTP/1.1 407 Proxy Authentication Required" CRLF
		  SERVER_HEADER HTML_CONTENT_HEADER
		  "Proxy-Authenticate: NTLM" CRLF) < 0) {
    goto cleanup;
  }

  if(add_icap_respheader(is, "X-ICAP-RESPMOD-Profile: NoRESPMOD")){
    goto cleanup;
  }
  if(response_rewrite(is, &response_hdr, response_body, strlen(response_body))){
    goto cleanup;
  }

  ret = 0;
 cleanup:
  reset_ustring(&response_hdr);
  return 0;
}

int reqresp_ntlm_type2(struct icap_state *is, uint32_t nip) {
  const char *response_body = "NTLM authentication requested"; // xxx
  ustring response_hdr = USTRING_INITIALIZER;
  int ret = -1;
  char *ntlmdata = NULL;
  void *challenge = NULL;

  challenge = ntlm_gen_challenge(nip);
  if(!challenge) {
    goto cleanup;
  }
  ntlmdata = ntlm_gen_type2(challenge);
  if(!ntlmdata) {
    goto cleanup;
  }

  if(printUString(&response_hdr,
		  "HTTP/1.1 407 Proxy Authentication Required" CRLF
		  SERVER_HEADER HTML_CONTENT_HEADER
		  "Proxy-Authenticate: NTLM %s" CRLF,
		  ntlmdata) < 0) {
    goto cleanup;
  }

  if(add_icap_respheader(is, "X-ICAP-RESPMOD-Profile: NoRESPMOD")){
    goto cleanup;
  }
  if(response_rewrite(is, &response_hdr, response_body, strlen(response_body))){
    goto cleanup;
  }

  ret = 0;
 cleanup:
  reset_ustring(&response_hdr);
  Free(ntlmdata);
  Free(challenge);
  return ret;
}

char* gen_ntlm_cookie_data(uint32_t nip, unsigned int uid, long ts) {
  ustring uscd = USTRING_INITIALIZER;
  ustring id = USTRING_INITIALIZER;
  uint8_t hmac[20];
  char hex_hmac[41];
  char *enc = NULL;

  if(printUString(&id, "n%u$%ld$%u", uid, ts, nip) < 0) {
    goto cleanup;
  }

  HMAC(EVP_sha1(), internal_hmac_key, sizeof(internal_hmac_key),
		  (const unsigned char *)id.string, id.current, hmac, 0);
  asciitohex(hmac, hex_hmac, EOF, sizeof(hmac));

  if(printUString(&uscd,
		  AUTH_DOM_COOKIE_TOKEN "=%ld-%s; path=/\n"
		  AUTH_DOM_COOKIE_USER "=n%u; path=/",
		  ts,
		  hex_hmac,
		  uid
		  ) < 0){
    goto cleanup;
  }

  enc = encrypt_data((const void*)poldata_key, strlen(poldata_key),
		     (const unsigned char*)uscd.string, uscd.current + 1);

cleanup:
  reset_ustring(&uscd);
  reset_ustring(&id);
  return enc;
}

int set_ntlm_cookies(icap_state *is, const char *enccook) {
  char *dec = NULL, *tok, *str, *enc = NULL;
  size_t len_output = 0;
  int ret = -1;

  enc = Strdup(enccook);
  if(!enc) {
    goto cleanup;
  }

  dec = (char*)decrypt_data((const void*)poldata_key, strlen(poldata_key),
			     enc, &len_output);
  if(!len_output) {
    nag("Zero output\n");
    goto cleanup;
  }

  if(dec[len_output - 1] != '\0') {
    nag("Missing null termination\n");
    goto cleanup;
  }

  str = dec;
  while((tok = strsep(&str, "\n"))) {
      if(add_icap_http_header(is, "Set-Cookie:", tok)) {
	goto cleanup;
      }
  }

  ret = 0;
 cleanup:
  Free(enc);
  Free(dec);
  return ret;
}
