#ifndef NTLMV2_H
#define NTLMV2_H

#include <time.h>

void *ntlmv2_gen_hash_t16(const char *user, const char *targetu16, size_t tlen, const void *ntlm_hash);
void *ntlmv2_gen_hash(const char *user, const char *target, const void *ntlm_hash);
int ntlmv2_verify_password(const unsigned char *ntlmrespbuf, size_t ntlmresplen,
			   const void *challenge, const void *ntlmv2_hash,
			   const void *target_info, size_t target_info_len,
			   time_t now);

#endif
