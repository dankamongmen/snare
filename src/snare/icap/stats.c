#include <stddef.h>
#include <stdint.h>
#include <snare/icap/stats.h>
#include <snare/icap/headers.h>
#include <snare/icap/request.h>
#include <libdank/utils/time.h>
#include <libdank/utils/syswrap.h>
#include <libdank/objects/objustring.h>

// FIXME redo all of this with Xmacros
typedef struct icap_stats {
	struct {
		uintmax_t begun,ok,fail,inc;
		avgmax_stats icaptt,icaptxt;
		uintmax_t verdicts[VERDICT_COUNT];
	} permethod[ICAP_METHOD_COUNT];
	uintmax_t trailers,trailer_lines;
	uintmax_t verdicts_postconn;
	uintmax_t oqueue_headers,oqueue_bodies;
	uintmax_t oqueue_header_octets,oqueue_body_octets;
	uintmax_t oqueue_recycled,oqueue_stack,oqueue_created;
	uintmax_t connections;
	uintmax_t nomod,noverdict;
	uintmax_t no_httpbody,no_httphdrs,bad_http_reqline,bad_http_request;
	uintmax_t httpdupheader;
	uintmax_t icap_thisquanta;
	uintmax_t lateverdicts,pipeline_violations;
	struct timeval icap_timer;
	avgmax_stats oqueuett,tps;
	uintmax_t gzip_unused,gzip_native,gzip_server;
	uintmax_t gzip_inserted,gzip_preload,gzip_postload;
	uintmax_t inflateerr,deflateerr;
	uintmax_t chunks_gzipped,chunks_gunzipped;
	intmax_t gzip_front_octets,gzip_back_octets;
} icap_stats;

static icap_stats stats;

#define INC_STAT(stat) void inc_##stat(void){ ++stats.stat; }
INC_STAT(connections);
INC_STAT(nomod);
INC_STAT(noverdict);
INC_STAT(trailers);
INC_STAT(trailer_lines);
INC_STAT(verdicts_postconn);
INC_STAT(oqueue_headers);
INC_STAT(oqueue_bodies);
INC_STAT(oqueue_recycled);
INC_STAT(oqueue_created);
INC_STAT(no_httpbody);
INC_STAT(no_httphdrs);
INC_STAT(lateverdicts);
INC_STAT(pipeline_violations);
INC_STAT(bad_http_reqline);
INC_STAT(bad_http_request);
INC_STAT(httpdupheader);
INC_STAT(gzip_unused);
INC_STAT(gzip_native);
INC_STAT(gzip_server);
INC_STAT(gzip_inserted);
INC_STAT(gzip_preload);
INC_STAT(gzip_postload);
INC_STAT(inflateerr);
INC_STAT(deflateerr);
INC_STAT(chunks_gzipped);
INC_STAT(chunks_gunzipped);
#undef INC_STAT

#define INC_STAT_ARG(type,stat) void inc_##stat(type inc){ stats.stat += inc; }
INC_STAT_ARG(off_t,oqueue_header_octets);
INC_STAT_ARG(off_t,oqueue_body_octets);
INC_STAT_ARG(intmax_t,gzip_front_octets);
INC_STAT_ARG(intmax_t,gzip_back_octets);
INC_STAT_ARG(uintmax_t,oqueue_stack);
#undef INC_STAT_ARG

void inc_verdicts(icap_method method,verdict v){
	++stats.permethod[method].verdicts[v];
}

#define INC_PERMETHOD_STAT(stat) \
void inc_method_##stat(icap_method method){ \
	++stats.permethod[method].stat; \
}
INC_PERMETHOD_STAT(begun);
#undef INC_PERMETHOD_STAT
#define INC_PERMETHOD_STAT(stat) \
void inc_method_##stat(icap_method *method){ \
	++stats.permethod[*method].stat; \
	*method = ICAP_METHOD_COUNT; \
}
INC_PERMETHOD_STAT(ok);
INC_PERMETHOD_STAT(fail);
INC_PERMETHOD_STAT(inc);
#undef INC_PERMETHOD_STAT

int stringize_avgmax_stat(ustring *u,const char *tag,const avgmax_stats *ams){
	if(printUString(u,"<%s><avg>%ju</avg><max>%ju</max></%s>",
				tag,ams->avg,ams->max,tag) < 0){
		return -1;
	}
	return 0;
}

int stringize_curmax_stat(ustring *u,const char *tag,const curmax_stats *cms){
	if(printUString(u,"<%s><cur>%ju</cur><max>%ju</max></%s>",
				tag,cms->cur,cms->max,tag) < 0){
		return -1;
	}
	return 0;
}

uintmax_t time_avgmax(avgmax_stats *ms,struct timeval *cur,const struct timeval *tv){
	uintmax_t t;

	Gettimeofday(cur,NULL);
	t = timeval_subtract_usec(cur,tv);
	adjust_avgmax_stats(ms,t);
	return t;
}

void time_icap_session(icap_method method,const struct timeval *tv){
	struct timeval cur;
	long i;

	time_avgmax(&stats.permethod[method].icaptt,&cur,tv);
	if((i = cur.tv_sec - stats.icap_timer.tv_sec) == 0){
		++stats.icap_thisquanta;
	}else{
		if(stats.icap_timer.tv_sec){
			adjust_avgmax_stats(&stats.tps,stats.icap_thisquanta);
			stats.icap_thisquanta = 0;
			// stirring in 0's will drag the average down pretty
			// quickly (log base 10 of the current average takes it
			// to 0), so this runs at most log(N) times -- and only
			// when we weren't doing any work anyway =]

			while(--i && stats.tps.avg){
				adjust_avgmax_stats(&stats.tps,0);
			}
		}
		stats.icap_timer.tv_sec = cur.tv_sec;
	}
}

#define INC_SIMPLE_TIMESTAT(name,stat) \
void time_##name(struct timeval *tv){ \
	struct timeval cur; \
	time_avgmax(&stats.stat,&cur,tv); \
	*tv = cur; \
}
INC_SIMPLE_TIMESTAT(oqueue_session,oqueuett);
#undef INC_SIMPLE_TIMESTAT

#define INC_PERMETHOD_TIMESTAT(name,stat) \
void time_##name(icap_method method,struct timeval *tv){ \
	struct timeval cur; \
	time_avgmax(&stats.permethod[method].stat,&cur,tv); \
	*tv = cur; \
}
INC_PERMETHOD_TIMESTAT(icap_tx,icaptxt);
#undef INC_PERMETHOD_TIMESTAT

void clear_icap_stats(void){
	clear_icap_header_stats();
	memset(&stats,0,sizeof(stats));
}

int stringize_icap_stats(ustring *u){
	const icap_stats *is = &stats;
	icap_method method;
	const struct {
		const char *tag;
		size_t offset;
		int signedp;
	} mmstatmap[] = {
		#define ICAP_AVGMAX_STAT(stat) \
			{ .tag = #stat, .offset = offsetof(icap_stats,stat), }
		ICAP_AVGMAX_STAT(oqueuett),
		ICAP_AVGMAX_STAT(tps),
		{ .tag = NULL, .offset = 0, }
		#undef ICAP_AVGMAX_STAT
	}, statmap[] = {
		#define ICAP_STAT(stat) \
			{ .tag = #stat, .offset = offsetof(icap_stats,stat), }
		#define ICAP_SIGNED_STAT(stat) \
			{ .tag = #stat, .offset = offsetof(icap_stats,stat), .signedp = 1,}
		ICAP_STAT(connections),
		ICAP_STAT(nomod),
		ICAP_STAT(noverdict),
		ICAP_STAT(verdicts_postconn),
		ICAP_STAT(oqueue_headers),
		ICAP_STAT(oqueue_bodies),
		ICAP_STAT(oqueue_header_octets),
		ICAP_STAT(oqueue_body_octets),
		ICAP_STAT(oqueue_created),
		ICAP_STAT(oqueue_recycled),
		ICAP_STAT(oqueue_stack),
		ICAP_STAT(trailers),
		ICAP_STAT(trailer_lines),
		ICAP_STAT(no_httpbody),
		ICAP_STAT(no_httphdrs),
		ICAP_STAT(lateverdicts),
		ICAP_STAT(pipeline_violations),
		ICAP_STAT(bad_http_reqline),
		ICAP_STAT(bad_http_request),
		ICAP_STAT(httpdupheader),
		ICAP_STAT(gzip_unused),
		ICAP_STAT(gzip_native),
		ICAP_STAT(gzip_server),
		ICAP_STAT(gzip_inserted),
		ICAP_STAT(gzip_preload),
		ICAP_STAT(gzip_postload),
		ICAP_STAT(inflateerr),
		ICAP_STAT(deflateerr),
		ICAP_STAT(chunks_gzipped),
		ICAP_STAT(chunks_gunzipped),
		ICAP_SIGNED_STAT(gzip_front_octets),
		ICAP_SIGNED_STAT(gzip_back_octets),
		{ .tag = NULL, .offset = 0, }
		#undef ICAP_SIGNED_STAT
		#undef ICAP_STAT
	},*cur;

	#define ICAP_STATS_TAG "icap_stats"
	if(printUString(u,"<" ICAP_STATS_TAG ">") < 0){
		return -1;
	}
	for(method = 0 ; method != ICAP_METHOD_COUNT ; ++method){
		const char *methname;
		verdict ver;

		if((methname = name_icap_method(method)) == NULL){
			continue;
		}
		#define METHOD_BEGUNSTR "init"
		#define METHOD_OKSTR "ok"
		#define METHOD_FAILSTR "fail"
		#define METHOD_INCSTR "inc"
		if(printUString(u,"<%s>"
			"<" METHOD_BEGUNSTR ">%ju</" METHOD_BEGUNSTR ">"
			"<" METHOD_OKSTR ">%ju</" METHOD_OKSTR ">"
			"<" METHOD_FAILSTR ">%ju</" METHOD_FAILSTR ">"
			"<" METHOD_INCSTR ">%ju</" METHOD_INCSTR ">",
			methname,is->permethod[method].begun,
				is->permethod[method].ok,
				is->permethod[method].fail,
				is->permethod[method].inc) < 0){
			return -1;
		}
		#undef METHOD_INCSTR
		#undef METHOD_FAILSTR
		#undef METHOD_OKSTR
		#undef METHOD_BEGUNSTR
		if(stringize_avgmax_stat(u,"icaptt",&is->permethod[method].icaptt)){
			return -1;
		}
		if(stringize_avgmax_stat(u,"icaptxt",&is->permethod[method].icaptxt)){
			return -1;
		}
		// We only want ERROR and DONE, not the transient COUNT/SKIP/TRICKLE
		for(ver = 0 ; ver < VERDICT_TRICKLE ; ++ver){
			const char *vname = name_verdict(ver);

			if(printUString(u,"<%s>%ju</%s>",vname,
			   is->permethod[method].verdicts[ver],vname) < 0){
				return -1;
			}
		}
		if(printUString(u,"</%s>",methname) < 0){
			return -1;
		}
	}
	if(stringize_icap_header_stats(u)){
		return -1;
	}
	for(cur = statmap ; cur->tag ; ++cur){
		uintmax_t s = *(const uintmax_t *)(((const char *)is) + cur->offset);

		if(cur->signedp){
			if(printUString(u,"<%s>%jd</%s>",cur->tag,(intmax_t)s,cur->tag) < 0){
				return -1;
			}
		}else{
			if(printUString(u,"<%s>%ju</%s>",cur->tag,s,cur->tag) < 0){
				return -1;
			}
		}
	}
	for(cur = mmstatmap ; cur->tag ; ++cur){
		const avgmax_stats *ms = (const avgmax_stats *)(((const char *)is) + cur->offset);

		if(stringize_avgmax_stat(u,cur->tag,ms)){
			return -1;
		}
	}
	if(printUString(u,"</" ICAP_STATS_TAG ">") < 0){
		return -1;
	}
	#undef ICAP_STATS_TAG
	return 0;
}
