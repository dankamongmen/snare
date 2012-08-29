#ifndef HANDLER_H
#define HANDLER_H

#include <stdint.h>
#include <sys/types.h>
#include <snare/oqueue.h>
#include <snare/verdicts.h>
#include "siteinfo.h"

#define BYPASS_TOKEN_PREFIX "scur-bp-token-"

struct icap_state;

int rep_init(void);
int rep_destroy(void);
verdict r_handler(struct oqueue_key *,struct icap_state *,icap_callback_e);

int check_bypass_token(const char *,char **);
int check_auth_cookie(char *, char *, uint32_t, time_t, long);
int check_auth_token(const char *, char **, uint32_t, unsigned int *, long *, time_t);

extern long auth_time_window;
extern unsigned char internal_hmac_key[HMAC_KEY_LEN];
extern char *auth_token_hmac_key;

// Malware stats. A single scan can result in both a detection and an error, if
// there was an error handling the detection.
void inc_maldetect(void);
void inc_malerror(void);
void inc_malclean(void);
void inc_maljumbo(void);
void inc_malbypass(void);
void inc_malbackuptx(void);
void dec_bonblocking(void);

#endif
