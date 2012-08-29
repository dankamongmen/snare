#ifndef SNARE_ICAP_REQUEST
#define SNARE_ICAP_REQUEST 

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <snare/writeq.h>
#include <snare/poller.h>
#include <snare/icap/status.h>
#include <snare/icap/headers.h>
#include <snare/icap/methods.h>
#include <libdank/utils/rfc2396.h>
#include <snare/icap/encapsulates.h>

struct pollinbuf;
struct pollfd_state;

// Masks for operating on statevec bitfields. All initialization states must be
// equivalent to 0 bits for reset_icap_state to work!
// FIXME: possible replacements/simplifications:
// 	0x01 <--> pfd->rxfxn->cb == rfc3507_pipeline_violation
// 	0x04 <--> !!icap->status
// 	0x08 <--> (!icap->encaps.added_headers && !icap_state_rewrittenp(icap) &&
// 			(hdrscratch_get_valid(icap->encaps.http.hdrs) ==
// 			icap->reqhdr_len + icap->resphdr_len))
// 0x01 rx is disabled, as is performed at the end of the rx chain if a
//      complete response has not yet been written.
#define ICAPSTATEMASK_RXDISABLED	0x01u
// 0x02 we're not using the (possibly null) body encapsulate as it was
//      received; instead, we're supplying our own (or are using null-body).
#define ICAPSTATEMASK_REWRITTEN		0x02u
// 0x04 we've enqueued some data for transmission (it's possibly been sent). at
//      this point, all we can do is stream, interrupt or interrupt-and-append.
#define ICAPSTATEMASK_TXSTARTED		0x04u
// 0x08 we've modified the content somehow, and thus can't send a 204 No Mod
//      (a superstate of ICAPSTATEMASK_REWRITTEN -- they could be combined into
//       a 2-bit state, if we found a fourth state. perhaps we ought anyway.)
#define ICAPSTATEMASK_MODIFIED		0x08u
// 0x10 if data is enqueued for write, we must go ahead and initiate the
//      transmission -- we're not currently waiting for TX callbacks.
#define ICAPSTATEMASK_TXALLOWED		0x10u
// 0x20 we must transcode prior to passing the data to the handler.
#define ICAPSTATEMASK_CBTRANSCODED	0x20u
// 0x40 we must transcode prior to transmitting the data.
#define ICAPSTATEMASK_TXTRANSCODED	0x40u

typedef struct icap_state {
	uri *icapuri;
	writeq wq;
	uintmax_t uuid;
	char *respheaders;
	unsigned statevec;
	icap_status status;
	icap_method method;
	icap_reqhdrs headers;
	const char *urimethod;
	struct pollinbuf *pibuf;
	icap_encapsulates encaps;
	struct timeval transstart,txstart;
} icap_state;

static inline int
icap_state_gotlastchunkp(const icap_state *is){
	return is->encaps.chunklen_current == 0;
}

static inline int
icap_state_txstartedp(const icap_state *is){
	return is->statevec & ICAPSTATEMASK_TXSTARTED;
}

static inline int
icap_state_rxdisabledp(const icap_state *is){
	return is->statevec & ICAPSTATEMASK_RXDISABLED;
}

static inline int
icap_state_rewrittenp(const icap_state *is){
	return is->statevec & ICAPSTATEMASK_REWRITTEN;
}

static inline int
icap_state_modifiedp(const icap_state *is){
	return is->statevec & ICAPSTATEMASK_MODIFIED;
}

static inline int
icap_state_txallowedp(const icap_state *is){
	return is->statevec & ICAPSTATEMASK_TXALLOWED;
}

static inline int
icap_state_rxtranscode(const icap_state *is){
	return is->statevec & (ICAPSTATEMASK_CBTRANSCODED | ICAPSTATEMASK_TXTRANSCODED);
}

static inline int
icap_state_cbtranscoded(const icap_state *is){
	return is->statevec & ICAPSTATEMASK_CBTRANSCODED;
}

static inline int
icap_state_txtranscoded(const icap_state *is){
	return is->statevec & ICAPSTATEMASK_TXTRANSCODED;
}

// NOT equivalent to !!is->status; we could have started responding without
// issuing a verdict. A verdict means "stop feeding me data; I renounce the
// ability to further analyze/modify the data." It also means that we can start
// sliding the window forward from the front; until a verdict is issued, we
// must retain the entirety of the data for scanning.
static inline int
icap_state_verdictp(const icap_state *is){
	return icap_state_txstartedp(is) && !is->encaps.body_tx_len;
}

static inline int
icap_state_txdonep(const icap_state *is){
	return writeq_emptyp(&is->wq) &&
		(icap_state_rewrittenp(is) ||
		(icap_state_gotlastchunkp(is) && icap_state_verdictp(is)));
}

static inline void
icap_state_setrxdisabled(icap_state *is){
	is->statevec |= ICAPSTATEMASK_RXDISABLED;
}

static inline void
icap_state_setmodified(icap_state *is){
	is->statevec |= ICAPSTATEMASK_MODIFIED;
}

static inline void
icap_state_setrewritten(icap_state *is){
	is->statevec |= ICAPSTATEMASK_REWRITTEN;
	icap_state_setmodified(is);
}

static inline void
icap_state_settxstarted(icap_state *is){
	is->statevec |= ICAPSTATEMASK_TXSTARTED;
}

static inline void
icap_state_settxtranscoded(icap_state *is,unsigned val){
	if(val){
		is->statevec |= ICAPSTATEMASK_TXTRANSCODED;
	}else{
		is->statevec &= ~ICAPSTATEMASK_TXTRANSCODED;
	}
}

static inline void
icap_state_settxallowed(icap_state *is,unsigned val){
	if(val){
		is->statevec |= ICAPSTATEMASK_TXALLOWED;
	}else{
		is->statevec &= ~ICAPSTATEMASK_TXALLOWED;
	}
}

static inline void
icap_state_setcbtranscoded(icap_state *is,unsigned val){
	if(val){
		is->statevec |= ICAPSTATEMASK_CBTRANSCODED;
	}else{
		is->statevec &= ~ICAPSTATEMASK_CBTRANSCODED;
	}
}

int stringize_icap_state(ustring *,const icap_state *);

int icap_want_startline(struct pollfd_state *,char *);

struct icap_state *create_icap_state(void)
	__attribute__ ((warn_unused_result)) __attribute__ ((malloc));

int free_icap_state(icap_state *);

// Warn if error is ignored, as this is for reuse-intended objects
int reset_icap_state(icap_state *) __attribute__ ((warn_unused_result));

int icap_want_startline(struct pollfd_state *,char *);

int add_icap_respheader(icap_state *,const char *)
	__attribute__ ((warn_unused_result));

static inline icap_state *
get_pfd_icap(struct pollfd_state *pfd){
	return (icap_state *)get_pfd_state(pfd);
}

static inline const icap_state *
get_const_pfd_icap(const struct pollfd_state *pfd){
	return (const icap_state *)get_const_pfd_state(pfd);
}

#ifdef __cplusplus
}
#endif

#endif
