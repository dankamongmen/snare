#include <stddef.h>
#include <snare/oqueue.h>
#include <snare/config.h>
#include <snare/pollinbuf.h>
#include <snare/icap/stats.h>
#include <libdank/utils/fds.h>
#include <snare/icap/methods.h>
#include <snare/icap/request.h>
#include <snare/icap/response.h>
#include <libdank/utils/parse.h>
#include <libdank/utils/string.h>
#include <libdank/utils/threads.h>
#include <libdank/utils/syswrap.h>
#include <libdank/utils/rfc2396.h>
#include <libdank/utils/memlimit.h>
#include <snare/icap/compression.h>
#include <libdank/objects/crlfreader.h>

#define ICAP_VERSION_STR "ICAP/1.0"
static int
parse_icap_version(char **buf){
	parse_whitespaces(buf);
	if(strncasecmp(*buf,ICAP_VERSION_STR,__builtin_strlen(ICAP_VERSION_STR))){
		bitch("Bad ICAP version: %s != %s\n",*buf,ICAP_VERSION_STR);
		return -1;
	}
	*buf += __builtin_strlen(ICAP_VERSION_STR);
	return 0;
}
#undef ICAP_VERSION_STR

// RFC 3507, 4.1. Following the start-line is a series of zero or more header
// lines, terminating in a blank line (nothing before the CRLF).
//
// 4.3 defines the headers.
static int
icap_want_headers(struct pollfd_state *pfd,char *header){
	icap_state *is = get_pfd_icap(pfd);

	// A blank line indicates the end of headers (*NOT* WS CRLF).
	if(strcmp(header,CRLF) == 0){
		return begin_encapsulate_extraction(pfd);
	}
	if(parse_icap_header(header,&is->headers)){
		return send_icapexception(pfd,ICAPSTATUS_BAD_REQUEST);
	}
	return 0;
}

static int
verify_icap_uri(uri *u,icap_state *icap){
	if(u->path == NULL){
		bitch("URI had no path component\n");
		return -1;
	}
	// Modules may enforce further restrictions on the query and userinfo
	// components; we need to use the hostname, method and path components
	// to match against the loaded configuration. The WebWasher ICAP client
	// is known to send "profile" information as a query component.
	if(is_reqmod_uri(u->path)){
		if(icap->method == ICAP_METHOD_OPTIONS || icap->method == ICAP_METHOD_REQMOD){
			icap->urimethod = "REQMOD";
			return 0;
		}
	}else if(is_respmod_uri(u->path)){
		if(icap->method == ICAP_METHOD_OPTIONS || icap->method == ICAP_METHOD_RESPMOD){
			icap->urimethod = "RESPMOD";
			return 0;
		}
	}
	return -1;
}

#define ICAP_URI_SCHEME "icap"
static int
parse_icap_startline(char *line,struct pollfd_state *pfd,icap_status *istat){
	icap_state *is = get_pfd_icap(pfd);
	const char *method;

	is->method = parse_method(&line);
	if(is->method == ICAP_METHOD_COUNT){
		*istat = ICAPSTATUS_METHOD_NOT_IMPLEMENTED;
		return -1;
	}
	if((method = name_icap_method(is->method)) == NULL){
		bitch("Couldn't stringize method %d\n",is->method);
		*istat = ICAPSTATUS_INTERNAL_ERROR;
		return -1;
	}
	// nag("Valid method: %s\n",method);
	inc_method_begun(is->method);
	if((is->icapuri = extract_uri(ICAP_URI_SCHEME,&line)) == NULL){
		*istat = ICAPSTATUS_BAD_REQUEST;
		return -1;
	}
	if(verify_icap_uri(is->icapuri,is)){
		bitch("Bad URI for %s\n",method);
		free_uri(&is->icapuri);
		*istat = ICAPSTATUS_METHOD_BAD_SERVICE;
		return -1;
	}
	if(parse_icap_version(&line)){
		*istat = ICAPSTATUS_VERSION_NOT_SUPPORTED;
		return -1;
	}
	if(strcmp(line,CRLF)){
		bitch("Excess data after ICAP version (%zu/%zu)\n",
				strlen(line),__builtin_strlen(CRLF));
		*istat = ICAPSTATUS_BAD_REQUEST;
		return -1;
	}
	return 0;
}
#undef ICAP_URI_SCHEME

// RFC 3507, 4.1. All ICAP messages begin with a start-line, ala RFC 2822.
// Requests begin with a request line, responses begin with a status line. We
// are only expecting requests and thus request lines.
//
// 4.2. All ICAP requests specify the ICAP resource being requested from the
// server using an ICAP URI. This URI is dictated by RFC 2396. A request
// consists of a method (RESPMOD, REQMOD, OPTIONS), a URI, and an ICAP version.
int icap_want_startline(struct pollfd_state *pfd,char *line){
	icap_state *is = get_pfd_icap(pfd);
	icap_status icapcode;

	if(strcmp(line,CRLF) == 0){ // Skip blank lines per RFC 3507
		return 0;
	}
	Gettimeofday(&is->transstart,NULL);
	if(parse_icap_startline(line,pfd,&icapcode)){
		return send_icapexception(pfd,icapcode);
	}
	return use_crlf_mode(is->pibuf,icap_want_headers);
}

static int
prep_icap_state(icap_state *is){
	static uintmax_t uuid_counter; // FIXME not threadsafe!

	is->urimethod = NULL;
	is->uuid = uuid_counter++;
	is->method = ICAP_METHOD_COUNT;
	init_icap_encapsulates(&is->encaps);
	return use_crlf_mode(is->pibuf,icap_want_startline);
}

icap_state *create_icap_state(void){
	icap_state *ret;

	if( (ret = Malloc("ICAP session state",sizeof(*ret))) ){
		memset(ret,0,sizeof(*ret));
		if( (ret->pibuf = create_pollinbuf()) ){
			if(prep_icap_state(ret) == 0){
				init_writeq(&ret->wq);
				return ret;
			}
			free_pollinbuf(&ret->pibuf);
		}
		Free(ret);
	}
	return NULL;
}

// We should only have entries on the writeq if we're tearing down the session
// following an error. Prior to calling prep_icap_state(), everything should be
// zeroed out, just as it is immediately following the initial Malloc(),
// UNLESS prep_icap_state() explicitly sets it (in which case it's a dontcare).
int reset_icap_state(icap_state *is){
	int ret = 0;

	if(is){
		if(is->method != ICAP_METHOD_COUNT){
			bitch("incomplete process for %s\n",name_icap_method(is->method));
			inc_method_inc(&is->method);
		}
		free_uri(&is->icapuri);
		free_icap_reqheaders(&is->headers);
		ret |= freegzip_state(is);
		ret |= free_icap_encapsulates(&is->encaps);
		Free(is->respheaders);
		is->respheaders = NULL;
		reset_writeq(&is->wq);
		is->status = 0;
		is->statevec = 0;
		ret |= prep_icap_state(is);
	}
	return ret;
}

int free_icap_state(icap_state *is){
	int ret = 0;

	if(is){
		ret |= reset_icap_state(is);
		free_pollinbuf(&is->pibuf);
		Free(is);
	}
	return ret;
}

int add_icap_respheader(icap_state *is,const char *hdr){
	const char *cur;
	size_t len,hlen;
	char *tmp;

	nag("Adding ICAP header: %s\n",hdr);
	for(cur = hdr ; *cur ; ++cur){
		if(*cur == 0xd || *cur == 0xa){
			bitch("Illegal character (%u) in header %s\n",*cur,hdr);
			return -1;
		}
	}
	hlen = strlen(hdr);
	len = hlen + strlen(CRLF) + 1;
	if(is->respheaders){
		len += strlen(is->respheaders);
	}
	if((tmp = Realloc("response headers",is->respheaders,len)) == NULL){
		return -1;
	}
	is->respheaders = tmp;
	memcpy(tmp + len - hlen - strlen(CRLF) - 1,hdr,hlen);
	memcpy(tmp + len - strlen(CRLF) - 1,CRLF,strlen(CRLF) + 1);
	return 0;
}

int stringize_icap_state(ustring *u,const icap_state *is){
	if(is->urimethod){
		if(printUString(u,"<%s/>",is->urimethod) < 0){
			return -1;
		}
	}
	if(is->encaps.hdrs){
		if(stringize_oqueue_key(u,"hdrs",is->encaps.hdrs) < 0){
			return -1;
		}
	}
	if(is->encaps.body){
		if(stringize_oqueue_key(u,"body",is->encaps.body) < 0){
			return -1;
		}
	}
	if(is->encaps.drainbody){
		if(stringize_oqueue_key(u,"drain",is->encaps.drainbody) < 0){
			return -1;
		}
	}
	if(is->encaps.transbody){
		if(stringize_oqueue_key(u,"trans",is->encaps.transbody) < 0){
			return -1;
		}
	}
	return 0;
}
