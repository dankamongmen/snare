#ifndef SNARE_OQUEUE
#define SNARE_OQUEUE

#include <zlib.h>
#include <snare/server.h>
#include <snare/poller.h>
#include <snare/verdicts.h>
#include <snare/pollinbuf.h>
#include <libdank/objects/filewindow.h>

struct writeq;
struct oqueue_key;
struct icap_state;

typedef enum {
	ICAP_CALLBACK_HEADERS,
	ICAP_CALLBACK_INCOMPLETE_BODY,
	ICAP_CALLBACK_BODY, 
} icap_callback_e;

typedef verdict (*oqueue_infxn)(struct oqueue_key *,
		struct icap_state *,icap_callback_e);

int init_oqueue(const char *,oqueue_infxn)
		__attribute__ ((warn_unused_result));

int kill_oqueue(void);

struct oqueue_key *create_icap_encapsulate(const char *)
		__attribute__ ((warn_unused_result));

int writen_icap_encapsulate(struct oqueue_key *,const void *,size_t);
int rewriten_icap_encapsulate(struct oqueue_key *,const void *,size_t)
				__attribute__ ((warn_unused_result));
int drainchunk_icap_encapsulate(struct oqueue_key *,struct pollinbuf *,
				size_t,chunkdumper_cb)
				__attribute__ ((warn_unused_result));
int readchunk_icap_encapsulate(struct oqueue_key *,struct pollinbuf *,
				size_t,chunkdumper_cb)
				__attribute__ ((warn_unused_result));
int printf_icap_encapsulate(struct oqueue_key *,const char *,...)
				__attribute__ ((format (printf,2,3)))
				__attribute__ ((warn_unused_result));
int deflate_icap_encapsulate(struct oqueue_key *,z_stream *,size_t *)
				__attribute__ ((warn_unused_result));
int inflate_icap_encapsulate(struct oqueue_key *,z_stream *,size_t,size_t *)
				__attribute__ ((warn_unused_result));

int window_icap_encapsulate(struct oqueue_key *,size_t)
		__attribute__ ((warn_unused_result));

int queue_icap_encapsulate(struct oqueue_key *,struct pollfd_state *,
		icap_callback_e,size_t) __attribute__ ((warn_unused_result));
int oqueue_passverdict_internal(struct oqueue_key **,verdict);

int free_icap_encapsulate(struct oqueue_key **);
int orphan_icap_encapsulate(struct oqueue_key **);

int stringize_oqueue_key(ustring *,const char *,const struct oqueue_key *);

typedef struct oqueue_key {
	size_t usedlen; // virtoff <= usedlen <= totallen (usedlen is virtual)
	// We slide a window over the data, unmapping chunks as they're no
	// longer needed. usedlen refers to a "virtual" map, the beginning of
	// which we may no longer have. Internally, they must be offset by this
	// "virtoff", representing data that's been released.
	scratchfile_window sw;
	int refcount;
	char *fname;
	// What we hand off might not correspond to what we transmit, due to
	// use of transcodings. Since only one partial queue can be active at
	// once (a partial and a complete can be simultaneously active, but a
	// complete needn't store the txlen -- it can use the cbkey's ->usedlen
	// directly), we update last_tx_point on partial handoffs. FIXME this
	// is being set, but nowhere used! use it or lose it. this is likely an
	// indication of a bug on TX of transcoded data...
	size_t allows_tx_through;
	struct pollfd_state *cbarg;
	struct timeval queuetime;
	// FIXME we could overload cbarg in a union and smash this in there
	// with it, since they're never being used at the same time...
	struct oqueue_key *next;
} oqueue_key;

// The current virtual (relative to the beginning of the file) length. This is
// the total amount of data we've read into this oqueue; we may no longer have
// all of it mapped.
static inline size_t
oqueue_usedlen(const oqueue_key *okey){
	return okey->usedlen;
}

static inline size_t
oqueue_inc_usedlen(oqueue_key *okey,size_t delta){
	return okey->usedlen += delta;
}

static inline size_t
oqueue_dec_usedlen(oqueue_key *okey,size_t delta){
	return okey->usedlen -= delta;
}

// A pointer to the buffer at a given virtual offset, or NULL on invalid offset
static inline char *
oqueue_ptrto(oqueue_key *okey,size_t off){
	return scratchfile_window_ptrto(&okey->sw,off);
}

static inline const char *
oqueue_const_ptrto(const oqueue_key *okey,size_t off){
	return scratchfile_window_const_ptrto(&okey->sw,off);
}

#endif
