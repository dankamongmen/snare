#include <stddef.h>
#include <string.h>
#include <libdank/utils/parse.h>
#include <libdank/utils/string.h>
#include <libdank/objects/lexers.h>
#include <libdank/objects/logctx.h>
#include <libdank/utils/memlimit.h>
#include <snare/icap/headers.h>

struct hdrmap {
	size_t offset;
	const char *hdrname,*fieldname;
};

#define DECLAREFIELD(fname,hname) { 		\
	.hdrname = hname ":",			\
	.offset = offsetof(icap_reqhdrs,fname),	\
	.fieldname = hname,			\
}
#define DECLAREIDENTFIELD(fname) DECLAREFIELD(fname,#fname)
// Taken from RFC3507 section 4.3
static struct hdrmap hdrtable[] = {
	DECLAREIDENTFIELD(allow),
	DECLAREIDENTFIELD(host),
	DECLAREIDENTFIELD(encapsulated),
	DECLAREFIELD(user_agent,"user-agent"),
	DECLAREFIELD(client_ipstr,"x-client-ip"),
	DECLAREFIELD(server_ipstr,"x-server-ip"),
	DECLAREFIELD(proxy_ipstr,"x-proxy-addr"),
	DECLAREFIELD(proxy_port,"x-proxy-port"),
	DECLAREFIELD(encapsulated_protocol,"x-encapsulated-protocol"),
	DECLAREFIELD(scan_progress_interval,"x-scan-progress-interval"),
	DECLAREFIELD(chunk_extensions,"x-chunk-extensions"),
	DECLAREIDENTFIELD(preview),
	DECLAREIDENTFIELD(date),
	DECLAREIDENTFIELD(expires),
	DECLAREIDENTFIELD(pragma),
	DECLAREIDENTFIELD(trailer),
	DECLAREIDENTFIELD(upgrade),
	DECLAREIDENTFIELD(authorization),
	DECLAREIDENTFIELD(from),
	DECLAREIDENTFIELD(connection),
	DECLAREFIELD(cache_control,"cache-control"),
	DECLAREIDENTFIELD(referer),
	{
		.hdrname = NULL,
		.fieldname = NULL,
		.offset = sizeof(icap_reqhdrs),
	}
};
#undef DECLAREIDENTFIELD
#undef DECLAREFIELD

static struct {
	uintmax_t unknown_ext_count,unknown_nonext_count;
	uintmax_t known_dups[sizeof(hdrtable) / sizeof(*hdrtable)];
	uintmax_t known_count[sizeof(hdrtable) / sizeof(*hdrtable)];
} icap_header_stats;

void clear_icap_header_stats(void){
	memset(&icap_header_stats,0,sizeof(icap_header_stats));
}

int stringize_icap_header_stats(ustring *u){
	typeof(*hdrtable) *cur;

	for(cur = hdrtable ; cur->hdrname ; ++cur){
		uintmax_t s;

		if((s = icap_header_stats.known_count[cur - hdrtable]) == 0){
			continue;
		}
		if(printUString(u,"<%s>%ju</%s>",cur->fieldname,s,cur->fieldname) < 0){
			return -1;
		}
		if((s = icap_header_stats.known_dups[cur - hdrtable]) == 0){
			continue;
		}
		if(printUString(u,"<%s-dups>%ju</%s-dups>",cur->fieldname,s,cur->fieldname) < 0){
			return -1;
		}
	}
	if(icap_header_stats.unknown_ext_count){
		#define ICAP_UNKNOWN_EXT_HEADER_TAG "unknownhdr-extension"
		if(printUString(u,"<" ICAP_UNKNOWN_EXT_HEADER_TAG ">%ju</" ICAP_UNKNOWN_EXT_HEADER_TAG ">",
					icap_header_stats.unknown_ext_count) < 0){
			return -1;
		}
		#undef ICAP_UNKNOWN_EXT_HEADER_TAG
	}
	if(icap_header_stats.unknown_nonext_count){
		#define ICAP_UNKNOWN_NONEXT_HEADER_TAG "unknownhdr-non-extension"
		if(printUString(u,"<" ICAP_UNKNOWN_NONEXT_HEADER_TAG ">%ju</" ICAP_UNKNOWN_NONEXT_HEADER_TAG ">",
					icap_header_stats.unknown_nonext_count) < 0){
			return -1;
		}
		#undef ICAP_UNKNOWN_NONEXT_HEADER_TAG
	}
	return 0;
}

int parse_icap_header(const char *hdr,icap_reqhdrs *headers){
	typeof(*hdrtable) *cur;
	const char *c;

	parse_whitespace(&hdr);
	// FIXME Lame! Replace with automaton on US-ASCII alphabet
	for(cur = hdrtable ; cur->hdrname ; ++cur){
		if(strncasecmp(hdr,cur->hdrname,strlen(cur->hdrname)) == 0){
			char **curhdr = (char **)((char *)headers + cur->offset);
			const char *field = hdr + strlen(cur->hdrname);

			if(*curhdr){
				nag("Dropping old value %s\n",*curhdr);
				Free(*curhdr);
				*curhdr = NULL;
				++icap_header_stats.known_dups[cur - hdrtable];
			}else{
				++icap_header_stats.known_count[cur - hdrtable];
			}
			parse_whitespace(&field);
			// nag("%s %s",cur->hdrname,field);
			if((*curhdr = Strdup(field)) == NULL){
				return -1;
			}
			return 0;
		}
	}
	// Printing unknown headers is very useful for debugging, but it's
	// unsafe (can corrupt the terminal) unless we check for ctrl chars.
	// This also ends up providing a useful check against having misread
	// the previous request (ie, we're still in a binary chunk).
	for(c = hdr ; *c ; ++c){
		if(*c < 0 || (!isprint(*c) && !isspace(*c))){
			bitch("Got invalid header char %u\n",*c);
			return -1;
		}
	}
	// It's now safe to print the header we read.
	#define EXTHDR_PREFIX "x-"
	if(strncasecmp(hdr,EXTHDR_PREFIX,__builtin_strlen(EXTHDR_PREFIX)) == 0){
		nag("Got unknown extension header: %s",hdr);
		++icap_header_stats.unknown_ext_count;
	}else{
		nag("Unknown header: %s",hdr);
		++icap_header_stats.unknown_nonext_count;
	}
	#undef EXTHDR_PREFIX
	return 0;
}

void free_icap_reqheaders(icap_reqhdrs *headers){
	struct hdrmap *cur;

	for(cur = hdrtable ; cur->hdrname ; ++cur){
		char **field = (char **)((char *)headers + cur->offset);

		Free(*field);
		*field = NULL;
	}
}

int icap_headers_allow(const icap_reqhdrs *hdrs,icap_status status){
	const char *allow;
	uint8_t allowed;
	
	if((allow = hdrs->allow) == NULL){
		return 0;
	}
	parse_whitespace(&allow);
	if(lex_u8(&allow,&allowed)){
		return 0;
	}
	return allowed == status;
}
