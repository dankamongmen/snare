// Functions for Web Filter Agent header based authentication

#ifndef MOBCLT_H
#define MOBCLT_H

#include "mobile_client_utils/swps_authlib.h"
#include "policy/policy_shim.h"

void mobclt_init(void);

int mobclt_check_token(const char *pw, const char *url, const char *ver,
		       const char *user, const char *ts, const char *token,
		       char **decrypted_user);

int mobclt_auth(struct EntityContainer *aec,
		const char *company_id, const char *url, const char *ver,
		const char *user, const char *ts, const char *token,
		unsigned int *uid, unsigned int *pid, unsigned int *eid,
		unsigned int *gid);

#endif
