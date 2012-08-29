#include <ctype.h>
#include <string.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <libdank/utils/memlimit.h>
#include <libdank/objects/logctx.h>
#include "ntlm.h"
#include "ntlmv2.h"
#include "util/misc.h"
#include "ntlm_util/ntlm_util.h"

// Generate the NTLMv2 hash for the given user name, authentication target, and
// NTLM hash. Returns NULL on error. Result needs to be Free()ed.
void *ntlmv2_gen_hash_t16(const char *user, const char *targetu16, size_t tlen, const void *ntlm_hash) {
  char *upuser = NULL, *useru16 = NULL;
  unsigned char *usertarget = NULL;
  size_t ulen, i;
  void *result = NULL;

  upuser = Malloc("upuser", strlen(user) + 1);
  for(i = 0; i < strlen(user); ++i) {
    // xxx fixme
    // *user is utf8, so using toupper() will break if the user name contains
    // any non-ASCII characters
    upuser[i] = toupper(user[i]);
  }
  upuser[i] = '\0';

  useru16 = utf8_to_utf16le(upuser, &ulen);
  if(!useru16) {
    nag("Error during Unicode conversion\n");
    goto cleanup;
  }

  // Concatenate upper case user name in UTF-16LE and authentication target
  usertarget = Malloc("usertarget", ulen + tlen);
  if(!usertarget) {
    nag("Error allocating memory\n");
    goto cleanup;
  }

  (void)memcpy(usertarget, useru16, ulen);
  (void)memcpy(usertarget + ulen, targetu16, tlen);

  // Allocate buffer for result, an HMAC MD5 value
  result = Malloc("ntlmv2hash", MD5_DIGEST_LENGTH);
  if(!result) {
    nag("Error allocating memory for result\n");
    goto cleanup;
  }

  HMAC(EVP_md5(),
       ntlm_hash,		// The key for this is the NTLM (v1) hash
       MD4_DIGEST_LENGTH,	// ...which is an MD4 (four) hash.
       usertarget,
       ulen + tlen,
       result,			// large enough to hold an MD5 (five)
       NULL);

 cleanup:
  Free(upuser);
  Free(useru16);
  Free(usertarget);
  return result;
}

// Same as above, but takes a utf-8 target
void *ntlmv2_gen_hash(const char *user, const char *target, const void *ntlm_hash) {
  void *ret = NULL;
  char *targetu16 = NULL;
  size_t tlen;

  targetu16 = utf8_to_utf16le(target, &tlen);
  if(!targetu16) {
    goto cleanup;
  }
  
  ret = ntlmv2_gen_hash_t16(user, targetu16, tlen, ntlm_hash);

 cleanup:
  Free(targetu16);
  return ret;
}

// Verify the NTLMv2 response pointed to by ntlmrespbuf with a length of
// ntlmresplen that the client sent in its type 3 message. Challenge is the a
// pointer to the 8 byte challenge we sent in our type 2 message. Ntlmv2_hash
// is calculated based on the NTLM hash (MD4 of mangled user name, stored as
// hex in our policy file), the user name (again, yes), and the authentication
// target. Target_info and target_info_len are based on the target information
// block from our type 2 message. When provided, we assure that the client
// sent the right block back to us (and used it for its HMAC calculations). If
// its null, we don't check but parse the block to find its end. Now is the
// current result from time(0). The client timestamp is allowed to deviate in
// both directions by NTLM_RESPONSE_AUTH_WINDOW seconds.
int ntlmv2_verify_password(const unsigned char *ntlmrespbuf, size_t ntlmresplen,
			   const void *challenge, const void *ntlmv2_hash,
			   const void *target_info, size_t target_info_len,
			   time_t now) {
  int ret = -1;
  size_t blob_off = 16;
  size_t pos = 16;
  uint64_t ts, uxts;
  uint8_t hmac_ref[MD5_DIGEST_LENGTH];
  unsigned char *challengeblob = NULL;
  size_t bloblen;
  uint16_t type;
  uint16_t datalen;
  long delta;

  if(pos + 4 + 4 + 8 + 8 + 4 > ntlmresplen) {
    nag("NTLM buffer too short, length %zu\n", ntlmresplen);
    goto cleanup;
  }

  // Blob signature
  if(memcmp(ntlmrespbuf + pos, "\x01\x01\x00\x00", 4)) {
    nag("No blob signature\n");
    goto cleanup;
  }
  hexnag(ntlmrespbuf + pos, 4, "Blob sig");
  pos += 4;
  
  // Reserved value
  hexnag(ntlmrespbuf + pos, 4, "Reserved");
  pos += 4;

  // Timestamp
  ts = read_le_64(ntlmrespbuf + pos);
  uxts = (ts / 10000000) - 11644473600;
  delta = (long)now - (long)uxts;
  if(labs(delta) > NTLM_RESPONSE_TIME_WINDOW) {
    nag("Timestamp invalid: win_ts %ju, ux_ts %ju, delta %ld, max %ld\n",
	(uintmax_t)ts, (uintmax_t)uxts, delta, NTLM_RESPONSE_TIME_WINDOW);
    goto cleanup;
  }
  hexnag(ntlmrespbuf + pos, 8, "Timestamp: %ju, unix %ju", (uintmax_t)ts, (uintmax_t)uxts);
  pos += 8;

  // Client nonce
  hexnag(ntlmrespbuf + pos, 8, "Nonce");
  pos += 8;

  // Unknown (4 bytes)
  hexnag(ntlmrespbuf + pos, 4, "Unknown");
  pos += 4;

  // Target information data
  if(target_info) {
    // If the caller provides the target info we expect from the client in its
    // type 3 msg (based on what we sent in our type 2 msg), then compare and
    // skip it in the buffer.
    if(pos + target_info_len > ntlmresplen) {
      nag("Buffer too small for expected target info data\n");
      goto cleanup;
    }
    hexnag(ntlmrespbuf + pos, target_info_len, "Target info (%zu bytes)", target_info_len);
    if(memcmp(ntlmrespbuf + pos, target_info, target_info_len)) {
      nag("Target info does not match\n");
      hexnag(target_info, target_info_len, "expected");
      nag("pos %zu, len %zu, ti-len %zu\n", pos, ntlmresplen, target_info_len);
      hexnag(ntlmrespbuf + pos + target_info_len, ntlmresplen - pos - target_info_len, "remaining data in response");
      goto cleanup;
    }
    pos += target_info_len;
  } else {
    // No target data provided by caller, we need to parse it to find the end.
    do {
      if(pos + 2 + 2 > ntlmresplen) {
	nag("NTLM buffer too short -- unterminated target information?\n");
	goto cleanup;
      }
      type = read_le_16(ntlmrespbuf + pos);
      pos += 2;
      datalen = read_le_16(ntlmrespbuf + pos);
      pos += 2;
      if(pos + datalen > ntlmresplen) {
	nag("NTLM buffer too short -- invalid datalen?\n");
	goto cleanup;
      }
      pos += datalen;
    } while(type); // type 0x0000 terminates this section
    if(datalen) {
      nag("Terminator subblock should have length 0, had length %u\n", (unsigned int)datalen);
    }
  }

  // Unknown (4 bytes)
  if(pos + 4 > ntlmresplen) {
    nag("NTLM buffer too short\n");
    goto cleanup;
  }
  hexnag(ntlmrespbuf + pos, 4, "Unknown");
  pos += 4;
  nag("We're at %zu, length %zu\n", pos, ntlmresplen);

  bloblen = pos - blob_off;
  nag("Blob is %zu bytes\n", bloblen);

  // Concatenate challenge and blob for HMAC calculation
  challengeblob = Malloc("challengeblog", bloblen + 8);	// Length of blob plus length of challenge
  if(!challengeblob) {
    goto cleanup;
  }
  (void)memcpy(challengeblob, challenge, 8);		// Challenge is 8 bytes
  (void)memcpy(challengeblob + 8, ntlmrespbuf + blob_off, bloblen);

  HMAC(EVP_md5(),		// Use HMAC MD5 on the input data
       ntlmv2_hash,		// Key is the NTLMv2 hash (an HMAC MD5 value)
       MD5_DIGEST_LENGTH,
       challengeblob,		// Input data is concatenation of challenge and blob
       bloblen + 8,		// Length of challenge (8 bytes) plus length of blob
       hmac_ref,		// Store result in hmac_ref
       NULL);
  
  // Compare HMAC the client provided (first 16 bytes, MD5_DIGEST_LENGTH, in the
  // NTLM response buffer) to the reference value we just calculated
  if(memcmp(hmac_ref, ntlmrespbuf, MD5_DIGEST_LENGTH)) {
    nag("HMAC mismatch, invalid password?\n");
    ret = 1;
    goto cleanup;
  }

  ret = 0;
 cleanup:
  Free(challengeblob);
  return ret;  
}
