#ifndef SNARE_ICAP_HTTP
#define SNARE_ICAP_HTTP 

#ifdef __cplusplus
extern "C" {
#endif

#include <libdank/objects/logctx.h>
#include <libdank/objects/objustring.h>

struct icap_encapsulates;

// When we remove a header, we overwrite it with 2 24-bit values -- the
// (positive) length of the stripe to be skipped, and the (non-negative) length
// of the following valid stripe (a length of 0 indicates that this skip ends
// the headers). This way, we can remove arbitrary headers in O(1) space. We
// require one such datum to indicate the length of the first valid buffer, as
// well; there, the skip stripe's bits are only interpreted as 0 or 1, with 0
// corresponding to "no skip buffers" (otherwise, we don't know whether to
// interpret a skip buf following the initial valid buf). Since a 0-length
// writestripe indicates the end of the stripes, adjacent skipstripes must be
// coalesced; a removal can require at most two coalescings, both necessarily
// immediately next to the new skipstripe. Thus, if a removal is performed
// preceeding a skipstripe, increase the skiplength by that stripe's length,
// and hijack its validlength. Then, if the removal also follows a skipstripe,
// increase that skiplength by our skiplength, and hijack our validlength
// (possibly bubbled back from the skipstripe we preceeded). In any case, we
// write one and only one hdrscratch, and that to the "leftmost" skipstripe.
// We use 6 octets due to the lack of any W3C-issued single-letter headers,
// combined with the "X-" requirement, giving us a minimum length of 6 octets
// for any valid header: "??:?\r\n".
//
// Start word:
//   0: check buflen for skipscratch
//   n: n-octet validscratch begins (check buflen for skipscratch)
//
// Begin:
//   curoff <- 0
//   if ((n = startword) == 0), goto Iterate
//   write n octets
//   curoff <- n
//
// Iterate:
//   is curoff == buflen? if so, FIN
//   skip, valid <- scratchbuf at curoff
//   curoff <- curoff + skip
//   write valid octets
//   curoff <- curoff + valid
//   goto Iterate
//
#define HDRSCRATCH_FIELD_BITS 24

// FIXME these seem to be getting interpreted as ints! hence accessors...why?
typedef struct hdrscratch {
	unsigned skip:  HDRSCRATCH_FIELD_BITS;
	unsigned valid: HDRSCRATCH_FIELD_BITS;
} hdrscratch;

static inline unsigned
hdrscratch_get_valid(const hdrscratch *hs){
	return hs->valid;
}

static inline unsigned
hdrscratch_get_skip(const hdrscratch *hs){
	return hs->skip;
}

// Can't pass a pointer to a bitfield member :/
#define hdrscratch_set_field(field,len) \
	if((len) >= (1 << HDRSCRATCH_FIELD_BITS)){ \
		bitch("Set of %zu would overflow %d-bit field\n",len,HDRSCRATCH_FIELD_BITS); \
		return -1; \
	} \
	/* nag("Setting %s: %zu\n",#field,len); */ \
	(field) = (len); \
	return 0;

static inline int
hdrscratch_set_valid(hdrscratch *hs,size_t len){
	// nag("Setting valid %zu\n",len);
	hdrscratch_set_field(hs->valid,len);
}

static inline int
hdrscratch_set_skip(hdrscratch *hs,size_t len){
	// nag("Setting skip %zu\n",len);
	hdrscratch_set_field(hs->skip,len);
}

static inline hdrscratch *
hdrscratch_at(void *v,size_t off){
	return (hdrscratch *)((unsigned char *)v + off);
}

static inline const hdrscratch *
hdrscratch_const_at(const void *v,size_t off){
	return (const hdrscratch *)((const unsigned char *)v + off);
}

static inline void
set_hdrscratch(hdrscratch *hs,unsigned skip,unsigned valid){
	hs->skip = skip;
	hs->valid = valid;
}

int init_http_hdrscratch(struct icap_encapsulates *);

typedef struct icap_http_headers {
	hdrscratch startword;
	size_t startlinelen;	// updated on startline rewrite
	char *new_startline;	// only non-NULL if there was a rewrite
	char *original_startline;
	char *method,*httpver,*rawuri;
	char *original_statusline;
	char *statuscode,*httpresver,*exposition;
	// FIXME See bug 530: headers ought be tracked as indexes and offsets
	// into the header structure in which they are found. the index is the
	// position of the first header character; the length represents the
	// number of bytes from said index to its corresponding LF. Headers
	// spanning multiple lines will have only the first line recorded
	// FIXME. Eventually, I'd like to eliminate all of these, and just use
	// an accessor that keys into a trie (see bug 494). FIXME all these will
	// go to const in the meantime as of 530
	// const char *ip;
	char *server,*resp_server;
#define HTTP_REQHDR(hdr,varname) char *varname;
#define HTTP_RESPHDR(hdr,varname)
#define HTTP_HDR(hdr,varname) HTTP_REQHDR(hdr,varname)
#include "http_headers.h"
#undef HTTP_REQHDR
#undef HTTP_RESPHDR
#undef HTTP_HDR
#define HTTP_REQHDR(hdr,varname)
#define HTTP_RESPHDR(hdr,varname) char *resp_##varname;
#define HTTP_HDR(hdr,varname) HTTP_RESPHDR(hdr,varname)
#include "http_headers.h"
#undef HTTP_REQHDR
#undef HTTP_RESPHDR
#undef HTTP_HDR
} icap_http_headers;

typedef int(*httphdr_parsefxn)(const char *map,size_t begin,size_t end,
				icap_http_headers *hdrs);
int postparse_http_reqhdr(const char *,size_t,size_t,icap_http_headers *);
int postparse_http_reshdr(const char *,size_t,size_t,icap_http_headers *);

void free_icap_http_state(struct icap_http_headers *);

// FIXME these ought all go away, and instead one function will accept a string
// and match it against a trie
static inline
const char *httphdr_lookup_contentencoding(const icap_http_headers *hdrs){
	return hdrs->resp_contentencoding;
}

static inline
const char *httphdr_lookup_acceptencoding(const icap_http_headers *hdrs){
	return hdrs->acceptencoding;
}

static inline
const char *httphdr_lookup_x_snare_varied(const icap_http_headers *hdrs){
	return hdrs->x_snare_varied;
}

int init_icap_http(void) __attribute__ ((warn_unused_result));
int stop_icap_http(void);

#ifdef __cplusplus
}
#endif

#endif
