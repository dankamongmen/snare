#ifndef SNARE_ICAP_STATS
#define SNARE_ICAP_STATS

#ifdef __cplusplus
extern "C" {   
#endif

#include <stdint.h>
#include <sys/types.h>
#include <snare/verdicts.h>
#include <snare/icap/methods.h>
#include <libdank/objects/objustring.h>

// FIXME replace most of the declarations here with Xmacros used in the .c file

// All stats are global to all threads.
void clear_icap_stats(void);
int stringize_icap_stats(struct ustring *);

// ICAP stats
void inc_connections(void);
void inc_nomod(void);
void inc_method_begun(icap_method);
void inc_method_ok(icap_method *);
void inc_method_fail(icap_method *);
void inc_method_inc(icap_method *);
void inc_pipeline_violations(void);

// HTTP encapsulate stats
void inc_trailers(void);
void inc_trailer_lines(void);
void inc_lateverdicts(void);
void inc_bad_http_reqline(void);
void inc_bad_http_request(void);
void inc_httpdupheader(void);
void inc_no_httpbody(void);
void inc_no_httphdrs(void);

// Verdict and oqueue stats, some of them per-method
void inc_verdicts(icap_method,verdict);
void inc_verdicts_postconn(void);
void inc_noverdict(void);
void inc_oqueue_headers(void);
void inc_oqueue_bodies(void);
void inc_oqueue_header_octets(off_t);
void inc_oqueue_body_octets(off_t);
void inc_oqueue_created(void);
void inc_oqueue_recycled(void);
void inc_oqueue_stack(uintmax_t);

struct timeval;

// These each update the timeval passed, so component timing might be performed
// accurately. These times must therefore be mutually exclusive!
void time_icap_tx(icap_method,struct timeval *);
void time_oqueue_session(struct timeval *);

void time_icap_session(icap_method,const struct timeval *);

// avgmax_stats generic periodic stat method...this belongs elsewhere FIXME
typedef struct curmax_stats {
	uintmax_t cur,max;
} curmax_stats;

typedef struct avgmax_stats {
	uintmax_t avg,max;
} avgmax_stats;

static inline void
adjust_avgmax_stats(avgmax_stats *ms,uintmax_t s){
	if(s > ms->max){
		ms->max = s;
	}
	ms->avg = ((ms->avg ? ms->avg : s) * 5 + s * 5) / 10;
}

static inline void
inc_curmax_stats(curmax_stats *cs){
	if(++cs->cur > cs->max){
		cs->max = cs->cur;
	}
}

static inline void
dec_curmax_stats(curmax_stats *cs){
	--cs->cur;
}

int stringize_avgmax_stat(struct ustring *,const char *,const avgmax_stats *);
int stringize_curmax_stat(struct ustring *,const char *,const curmax_stats *);

uintmax_t time_avgmax(avgmax_stats *,struct timeval *,const struct timeval *);

// Stats regarding the use of compression by clients and servers.
void inc_gzip_unused(void); // no advertisement of gzip capability
void inc_gzip_client(void); // gzip was requested but not applied
void inc_gzip_server(void); // gzip was not requested but was applied (error)
void inc_gzip_native(void); // client + server used gzip natively
void inc_gzip_inserted(void); // we modified the REQMOD to request compression
void inc_gzip_preload(void); // we got a compressed reply due to inserted req
void inc_gzip_postload(void); // we compressed an uncompressed response
void inc_deflateerr(void); // error during deflation
void inc_inflateerr(void); // error during inflation
void inc_chunks_gzipped(void); // we compressed a chunk
void inc_chunks_gunzipped(void); // we decompressed a chunk
void inc_gzip_front_octets(intmax_t); // compression savings due to gzip, front
void inc_gzip_back_octets(intmax_t); // compression savings due to gzip, front

#ifdef __cplusplus
}
#endif

#endif
