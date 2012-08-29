#ifndef PROXYAUTH_H
#define PROXYAUTH_H

#include <policy/policy_shim.h>

char *gen_authenticate_hdr(uint32_t, const unsigned char *, unsigned int, int);
int check_authorization_header(const char *, const char *, uint32_t,
			       const unsigned char *, unsigned int *,
			       unsigned int *, int *);

#endif
