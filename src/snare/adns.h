#ifndef SNARE_ADNS
#define SNARE_ADNS

#ifdef __cplusplus
extern "C"
#endif                                                                          

#include <adns.h>

struct pollfd;

typedef struct snare_dns_ctx {
	adns_state adns;
	struct pollfd * restrict fds,* restrict tmpfds;
	int numfds;
} snare_dns_ctx;

int init_snare_dns(snare_dns_ctx *);
int stop_snare_dns(snare_dns_ctx *);

int update_adns_fds(snare_dns_ctx *);

int issue_dns_request(snare_dns_ctx *,const char *,adns_query *);
int process_dns_replies(snare_dns_ctx *);

#define processfxn(toprocess) \
static inline \
int dns_fd_process##toprocess(snare_dns_ctx *sdc,int fd){ \
	struct timeval tv = { .tv_sec = 0, .tv_usec = 0, }; \
	return adns_process##toprocess(sdc->adns,fd,&tv); \
}
processfxn(readable)
processfxn(writeable)
processfxn(exceptional)
#undef processfxn

#ifdef __cplusplus                                                              
}
#endif                                                                          

#endif
