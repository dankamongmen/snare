#ifndef SNARE_ICAP_ENCAPSULATES
#define SNARE_ICAP_ENCAPSULATES

#ifdef __cplusplus
extern "C" {
#endif

#include <snare/verdicts.h>
#include <snare/icap/http.h>
#include <snare/icap/methods.h>
#include <snare/icap/compression.h>

// Ordering is important here; we enforce rules of RFC 3507 4.4.1's grammar by
// this ordering, and sum_encapsulates() also relies on it.
typedef enum {
	ICAP_ENCAPSULATE_HDR_REQUEST,
	ICAP_ENCAPSULATE_HDR_RESPONSE,
	ICAP_ENCAPSULATE_BODY_REQUEST,
	ICAP_ENCAPSULATE_BODY_RESPONSE,
	ICAP_ENCAPSULATE_BODY_OPTIONS,
	ICAP_ENCAPSULATE_BODY_NULL,
	ICAP_ENCAPSULATE_COUNT
} icap_encapsulate_types;

struct writeq;
struct oqueue_key;
struct pollfd_state;

typedef struct bufstripe {
	size_t off,len;
} bufstripe;

// We can have both header encapsulates in a given message, but one and only
// one of the four body encapsulates (request, response, options, null).
typedef struct icap_encapsulates {
	icap_encapsulate_types bodytype;
	size_t chunklen_current;
	
	// reqhdr_len and reshdr_len are calculated upon the ICAP Encapsulated
	// header being parsed, and thus match the default header data to
	// include in a non-204 response. As header changes are made by the
	// handler, these are updated; they thus always describe the header
	// encapsulates as they would be sent at that moment. They do *not*
	// necessarily continue to describe the oqueue_key buffer which stores
	// the original request-encapsulated data -- that data is not to be
	// directly used by the handler (use the header-mutating interfaces)!
	size_t reqhdr_len,reshdr_len;
	
	struct oqueue_key *hdrs,*body;
	
	size_t trailer_len;

	// If we're trickling, we can only transmit the body up through a given
	// approved offset.
	size_t body_tx_len,body_tx_off;

	// If we're rewriting, we still need to read the provided data, but we
	// don't want to read it in O(N) state. Using a different oqueue_key,
	// we can reset on each read (the rewritten data's in ->body).
	struct oqueue_key *drainbody;

	const struct zlib_interface *transapi;
	struct oqueue_key *transbody;
	z_stream zstream;

	icap_http_headers http;
} icap_encapsulates;

int begin_encapsulate_extraction(struct pollfd_state *)
       	__attribute__ ((warn_unused_result));

int prepare_icap_encapheader(int,struct writeq *,const icap_encapsulates *)
       	__attribute__ ((warn_unused_result));
int prepare_icap_empty_encapheader(int,struct writeq *)
       	__attribute__ ((warn_unused_result));

void init_icap_encapsulates(icap_encapsulates *);
int free_icap_encapsulates(icap_encapsulates *);

int icap_drain_chunkline(struct pollfd_state *,char *)
       	__attribute__ ((warn_unused_result));

int icap_drain_chunkdata(struct pollfd_state *)
       	__attribute__ ((warn_unused_result));

#ifdef __cplusplus
}
#endif

#endif
