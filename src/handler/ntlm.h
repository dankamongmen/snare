#ifndef NTLM_H
#define NTLM_H

#include <openssl/des.h>
#include "snare/icap/request.h"
#include "handler/siteinfo.h"
#include "ntlm_util/ntlm_util.h"

// This controls the validity interval of the cookie we set after doing an
// NTLM transaction. After the cookie expires, the client has to do NTLM
// again (we send another 407)
#define NTLM_AUTH_TIME_WINDOW 300	// 5 minutes

// This controls the maximum amount of time the timestamp in the client's
// NTLMv2 message is allowed to be off.
#define NTLM_RESPONSE_TIME_WINDOW 7200L	// 2 hours

extern unsigned char internal_hmac_key[HMAC_KEY_LEN];

typedef struct {
  char *domain, *user, *host;
} ntlm_type3_data;

int ntlm_verify_password(const unsigned char *ntlmbuf, size_t ntlmlen, const void *pw_md4, uint32_t nip);
int ntlm_verify_password_internal(const unsigned char *ntlmbuf, size_t ntlmlen, const void *pw_md4,
				  const void *challenge, const void *target_info, size_t target_info_len);
void des_parity_adjust(const unsigned char *key7, DES_cblock pkey);
int ntlm_response(const void *pw_md4, const void *challenge, unsigned char *response);

void free_type3_data(ntlm_type3_data*);
void reset_type3_data(ntlm_type3_data*);
int ntlm_decode_type3(const unsigned char *ntlmbuf, size_t ntlmlen, ntlm_type3_data *result);

char *ntlm_gen_type2(const void*);

int ntlm_check_if_type1(const void *ntlmbuf, size_t ntlmlen);

int reqresp_ntlm_challenge(struct icap_state *is);
int reqresp_ntlm_type2(struct icap_state *is, uint32_t nip);

char* gen_ntlm_cookie_data(uint32_t nip, unsigned int uid, long ts);
int set_ntlm_cookies(icap_state *is, const char *enccook);

#endif
