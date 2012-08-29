#ifndef SNARE_ICAP_RESPONSE
#define SNARE_ICAP_RESPONSE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <snare/icap/status.h>

struct oqueue_key;
struct icap_state;
struct pollfd_state;

// Send an ICAP error
int send_icapexception(struct pollfd_state *,icap_status)
	__attribute__ ((warn_unused_result));

// Edge-triggered callback for use with kqueue(EV_CLEAR) / epoll(EPOLLET)
int icap_tx_callback(struct poller *p __attribute__ ((unused)),struct pollfd_state *)
	__attribute__ ((warn_unused_result));

// Enqueue a chunk of tricklable data, initiating or continuing transmission,
// and optionally also send a 0-chunk
int send_icap_chunk(struct pollfd_state *,struct oqueue_key *,size_t,size_t,int)
	__attribute__ ((warn_unused_result));

// Invalidate the ISTag (see RFC 3507 4.7) due to a configuration change
void invalidate_istag(void);

int icap_callback(struct pollfd_state *,verdict,int)
	__attribute__ ((warn_unused_result));

#ifdef __cplusplus
}
#endif

#endif
