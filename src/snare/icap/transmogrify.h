#ifndef SNARE_ICAP_TRANSMOGRIFY
#define SNARE_ICAP_TRANSMOGRIFY

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <libdank/utils/rfc2396.h>

struct icap_state;

int rewrite_icap_http_startline_str(struct icap_state *,const char *)
	__attribute__ ((warn_unused_result));

int rewrite_icap_http_startline_flaturi(struct icap_state *,const char *,
					const char *,const char *)
	__attribute__ ((warn_unused_result));

int rewrite_icap_http_startline(struct icap_state *,const char *,
				const uri *,const char *)
	__attribute__ ((warn_unused_result));

// All of these expect a header of the form "Header:". We should eliminate the
// necessity to pass the ':' within the string -- it's confusing. FIXME Also,
// should it be possible to write a header with no value? We don't support it.
int add_icap_http_header(struct icap_state *,const char *,const char *)
	__attribute__ ((warn_unused_result));

int rewrite_icap_http_header(struct icap_state *,const char *,const char *)
	__attribute__ ((warn_unused_result));

int rewritefmt_icap_http_header(struct icap_state *,const char *,const char *,...)
	__attribute__ ((warn_unused_result));

int icap_request_rewrite(struct icap_state *,const char *,size_t,const char *,size_t)
	__attribute__ ((warn_unused_result));

int icap_response_rewrite(struct icap_state *,const char *,size_t,const char *,size_t)
	__attribute__ ((warn_unused_result));

int icap_trickle_payload(struct icap_state *,size_t)
	__attribute__ ((warn_unused_result));

#ifdef __cplusplus
	}
#endif

#endif
