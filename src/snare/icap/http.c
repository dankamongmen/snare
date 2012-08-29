#include <ctype.h>
#include <stddef.h>
#include <sys/mman.h>
#include <snare/oqueue.h>
#include <snare/icap/http.h>
#include <snare/icap/stats.h>
#include <libdank/utils/string.h>
#include <libdank/utils/syswrap.h>
#include <libdank/objects/lrupat.h>
#include <libdank/utils/memlimit.h>
#include <libdank/objects/logctx.h>
#include <snare/icap/encapsulates.h>
#include <libdank/objects/crlfreader.h>

static struct lrupat *hdrlrupat;

typedef int (*http_valuefxn)(const char *,size_t,icap_http_headers *); 

static int
set_default(const char *value,size_t vlen,icap_http_headers *headers,
		size_t offset,const char *description){
	char *tmp;

	if((tmp = Strndup(value,vlen)) == NULL){
		return -1;
	}
	// nag("%s <%s>\n",description,tmp);
	if(*(char **)((char *)headers + offset)){
		nag("Duplicated header: %s (%s->%s)\n",description,
			*(char **)((char *)headers + offset),tmp);
		inc_httpdupheader();
	}
	Free(*(char **)((char *)headers + offset));
	*(char **)((char *)headers + offset) = tmp;
	return 0;
}

#define SET_DEFAULT_REQHDR(field,description) \
static int \
set_##field(const char *value,size_t vlen,icap_http_headers *headers){ \
	return set_default(value,vlen,headers,offsetof(typeof(*headers),field),description); \
}

#define SET_DEFAULT_RESPHDR(field,description) \
static int \
set_resp_##field(const char *value,size_t vlen,icap_http_headers *headers){ \
	return set_default(value,vlen,headers,offsetof(typeof(*headers),resp_##field),description); \
}

#define SET_DEFAULT_SELFNAMED(field) \
 SET_DEFAULT_REQHDR(field,#field) SET_DEFAULT_RESPHDR(field,#field)

/* static int
set_nocopy(const char *value,size_t vlen __attribute__ ((unused)),icap_http_headers *headers,
		size_t offset,const char *desc __attribute__ ((unused))){

	// nag("%s <%.*s>\n",description,(int)vlen,value);
	*(const char **)((char *)headers + offset) = value;
	return 0;
}

#define SET_NOCOPY(field,description) \
static int \
set_##field(const char *value,size_t vlen,icap_http_headers *headers){ \
	return set_nocopy(value,vlen,headers,offsetof(typeof(*headers),field),description); \
}

#define SET_NOCOPY_SELFNAMED(field) SET_NOCOPY(field,#field) */

// FIXME all these ought move to SET_NOCOPY_SELFNAMED
// SET_DEFAULT_SELFNAMED(ip);
SET_DEFAULT_SELFNAMED(server);
#define HTTP_HDR(hdr,varname) SET_DEFAULT_SELFNAMED(varname)
#define HTTP_REQHDR(hdr,varname) SET_DEFAULT_REQHDR(varname,#varname)
#define HTTP_RESPHDR(hdr,varname) SET_DEFAULT_RESPHDR(varname,#varname)
#include "http_headers.h"
#undef HTTP_RESPHDR
#undef HTTP_REQHDR
#undef HTTP_HDR

static struct http_cb_map {
	const char *header;
	size_t headerlen;
	const http_valuefxn fxn;
	const http_valuefxn respfxn;
} http_cb_maps[] = {
//#define HTTP_DEF(x,cb) { .header = #x":", .headerlen = sizeof(#x":") - 1, .fxn = cb, }
#define HTTP_DEF(x,cb,respcb) { .header = #x, .headerlen = sizeof(#x) - 1, .fxn = cb, .respfxn = respcb, }
#define HTTP_HDR(hdr,varname) HTTP_DEF(hdr,set_##varname,set_resp_##varname),
#define HTTP_REQHDR(hdr,varname) HTTP_DEF(hdr,set_##varname,NULL),
#define HTTP_RESPHDR(hdr,varname) HTTP_DEF(hdr,NULL,set_resp_##varname),
  // xxx Why do we store the Server, Host, and X-Server-IP headers all in the same variable? This
  //     seems highly dubious to me...
	HTTP_DEF(Host,set_server,set_resp_server),
	// HTTP_DEF(X-Client-IP,set_ip),
	HTTP_DEF(X-Server-IP,set_server,set_resp_server),
	// HTTP_DEF(X-Forwarded-For,set_ip),
#include "http_headers.h"
#undef HTTP_RESPHDR
#undef HTTP_REQHDR
#undef HTTP_HDR
#undef HTTP_DEF
	{ .header = NULL, .headerlen = 0, .fxn = NULL, .respfxn = NULL, }
};

static int
match_http_header(icap_http_headers *hdrs,const char *line,size_t linelen,int responsep){
	const typeof(*http_cb_maps) *map;
	void *voidmap;
	ssize_t llen;

	if(lookup_lrupat_term_nocase(hdrlrupat,line,':',&voidmap) == 0){
		return 0;
	}
	map = voidmap;
	llen = map->headerlen;
	if(line[llen++] != ':'){
		nag("Empty match on %s\n",map->header);
		return 0;
	}
	while(isspace(line[llen])){
		++llen;
	}
	if(linelen - llen == 0){
		nag("Empty match on %s\n",map->header);
		return 0;
	}
	if(responsep){
		if(map->respfxn){
			return map->respfxn(line + llen,linelen - llen,hdrs);
		}
	}else{
		if(map->fxn){
			return map->fxn(line + llen,linelen - llen,hdrs);
		}
	}
	nag("Found %s in the wrong set of headers\n",map->header);
	return 0;
}

// See RFC2616 -- Request-Line = Method SP Request-URI SP HTTP-Version CRLF
// See RFC2817 -- Request-Line = CONNECT Authority HTTP-Version CRLF
// The caller will clean any assigned fields within hdrs upon an error return,
// so there's not need to clean them up on failure paths.
// ->method, ->rawuri, and ->httpver must be NULL upon entry.
static int
extract_http_startline(const char *startline,icap_http_headers *hdrs){
	size_t startlinelen = hdrs->startlinelen;
	const char *s = startline;

	if(startlinelen <= sizeof(CRLF)) {
		bitch("Empty startline\n");
		goto err;
	}
	if((hdrs->original_startline = Strndup(startline,startlinelen - (sizeof(CRLF) - 1))) == NULL){
		goto err;
	}
	while(startlinelen && !isspace(*startline)){ // get the method...
		--startlinelen;
		++startline;
	}
	if((!(startline - s)) || ((hdrs->method = Strndup(s,startline - s)) == NULL)){
		nag("Couldn't copy %zub method\n",startline - s);
		goto err;
	}
	while(startlinelen && isspace(*startline)){ // now the whitespace...
		--startlinelen;
		++startline;
	}
	s = startline;
	while(startlinelen && !isspace(*startline)){ // now the uri...
		--startlinelen;
		++startline;
	}
	if((!(startline - s)) || ((hdrs->rawuri = Strndup(s,startline - s)) == NULL)){
		nag("Couldn't copy %zub URI\n",startline - s);
		goto err;
	}
	while(startlinelen && isspace(*startline)){ // again, the whitespace...
		--startlinelen;
		++startline;
	}
	// FIXME if we're going to match against a list of constants, we may as
	// well just keep const char * references and save lots of copying
	if(startlinelen != strlen("HTTP/1.1"CRLF)){
		bitch("Not HTTP/1.[01]: %zu[%.*s]!\n",startlinelen,(int)startlinelen,startline);
		goto err;
	}
	if(strncmp(startline,"HTTP/1.1"CRLF,startlinelen) && strncmp(startline,"HTTP/1.0"CRLF,startlinelen)){
		bitch("Not HTTP/1.[01]: [%.*s]!\n",(int)startlinelen,startline);
		goto err;
	}
	if((hdrs->httpver = Strndup(startline,startlinelen - (sizeof(CRLF) - 1))) == NULL){
		goto err;
	}
	nag("[%s] [%s] [%s]\n",hdrs->method,hdrs->rawuri,hdrs->httpver);
	return 0;

err:
	nag("[%s] [%s] [%s]\n",hdrs->method ? hdrs->method : "unlexable",
			hdrs->rawuri ? hdrs->rawuri : "unlexable",
			hdrs->httpver ? hdrs->httpver : "unlexable");
	Free(hdrs->original_startline);
	hdrs->original_startline = NULL;
	Free(hdrs->method);
	hdrs->method = NULL;
	Free(hdrs->rawuri);
	hdrs->rawuri = NULL;
	Free(hdrs->httpver);
	hdrs->httpver = NULL;
	return -1;
}

// ->httpresver, ->statuscode, and ->exposition must be NULL upon entry.
static int
extract_http_statusline(const char *startline,icap_http_headers *hdrs){
	size_t startlinelen = hdrs->startlinelen;
	const char *s = startline;

	if((hdrs->original_statusline = Strndup(startline,startlinelen - (sizeof(CRLF) - 1))) == NULL){
		goto err;
	}

	while(startlinelen && !isspace(*startline)){ // get the method...
		--startlinelen;
		++startline;
	}
	// FIXME if we're going to match against a list of constants, we may as
	// well just keep const char * references and save lots of copying
	if(strncmp(s,"HTTP/1.1",startline - s) && strncmp(s,"HTTP/1.0",startline - s)){
		bitch("Not HTTP/1.[01]: [%.*s]!\n",(int)(startline - s),s);
		goto err;
	}
	if((!(startline - s)) || ((hdrs->httpresver = Strndup(s,startline - s)) == NULL)){
		nag("Couldn't copy %zub version\n",startline - s);
		goto err;
	}
	while(startlinelen && isspace(*startline)){ // now the whitespace...
		--startlinelen;
		++startline;
	}
	s = startline;
	while(startlinelen && !isspace(*startline)){ // now the uri...
		--startlinelen;
		++startline;
	}
	if((!(startline - s)) || ((hdrs->statuscode = Strndup(s,startline - s)) == NULL)){
		nag("Couldn't copy %zub URI\n",startline - s);
		goto err;
	}
	while(startlinelen && isspace(*startline)){ // again, the whitespace...
		--startlinelen;
		++startline;
	}
	s = startline;
	// FIXME this doesn't look sufficiently general re: lf/cr fun
	while(startlinelen && *startline != CRLF[0]){ // now the exposition...
		--startlinelen;
		++startline;
	}
	--startlinelen;
	++startline;
	if(startlinelen != 1 || *startline != CRLF[1]){
		bitch("Bogosity at end of %s %zu[%.*s]\n",s,startlinelen,(int)startlinelen,startline);
		goto err;
	}
	--startlinelen;
	++startline;
	if((!(startline - s)) || ((hdrs->exposition = Strndup(s,startline - s - (sizeof(CRLF) - 1))) == NULL)){
		goto err;
	}
	nag("[%s] [%s] [%s]\n",hdrs->httpresver,hdrs->statuscode,hdrs->exposition);
	return 0;

err:
	nag("[%s] [%s] [%s]\n",hdrs->httpresver ? hdrs->httpresver : "unlexable",
			hdrs->statuscode ? hdrs->statuscode : "unlexable",
			hdrs->exposition ? hdrs->exposition : "unlexable");
	Free(hdrs->original_statusline);
	hdrs->original_statusline = NULL;
	Free(hdrs->httpresver);
	hdrs->httpresver = NULL;
	Free(hdrs->statuscode);
	hdrs->statuscode = NULL;
	Free(hdrs->exposition);
	hdrs->exposition = NULL;
	return -1;
}

static inline int
add_header_entry(icap_http_headers *hdrs,const char *map,off_t offset,off_t len,int responsep){
	return match_http_header(hdrs,map + offset,(size_t)len,responsep);
}

typedef int(*startline_extractor)(const char *,icap_http_headers *);

// We are getting a memory-mapped buffer, *not* an ASCIIZ string! You must
// check against the remaining length before checking a character, rather than
// checking for the NUL terminator. Functions like strchr(), strspn() and
// strcspn() are not safe to use, in the general case!
// This might be called more than once per icap_http_headers, for instance if
// both request and response headers are present. Thus, before any calls it
// must be assured that icap_http_headers have been initialized; this function
// must not initialize them itself!
static int
postparse_http_headers(const char *map,size_t begin,size_t len,
		icap_http_headers *hdrs,startline_extractor extractfxn,
		int resphdrp){
	const char *mappos,*startline = NULL;
	size_t left,startlinelen = 0;
	int ret = 0;

	if(len == 0){
		bitch("Won't postparse empty HTTP headers!\n");
		return -1;
	}
	// nag("Headers: [%*s]\n",(int)len,map + begin);
	mappos = map + begin;
	left = len;
	while(left){
		const char *start;
		int crlf = 0;

		if(isspace(*mappos)){
			++mappos;
			--left;
			continue;
		}
		// mappos is not whitespace, and there is at least 1 character
		start = mappos++;
		// start is non-whitepsace. mappos is unknown. 0 chars possible
		while(--left){
			if(crlf && *mappos == CRLF[1]){
				crlf = 2;
				++mappos;
				--left;
				break;
			}
			crlf = 0;
			if(*mappos == CRLF[0]){
				crlf = 1;
			}
			++mappos; // left is decremented in loop cond
		}
		if(!startline){
			startlinelen = mappos - start;
			startline = start;
		}else{
			ret |= add_header_entry(hdrs,map,start - map,mappos - start - crlf,resphdrp);
		}
	}
	hdrs->startlinelen = startlinelen;
	if(startline){
		if(extractfxn(startline,hdrs)){
			inc_bad_http_reqline(); // startline failures only
			ret = -1;
		}
	}
	if(ret){
		free_icap_http_state(hdrs);
		inc_bad_http_request(); // for any failure
	}
	return ret;
}


int postparse_http_reqhdr(const char *map,size_t begin,size_t end,icap_http_headers *hdrs){
	return postparse_http_headers(map,begin,end,hdrs,extract_http_startline,0);
}

int postparse_http_reshdr(const char *map,size_t begin,size_t end,icap_http_headers *hdrs){
	return postparse_http_headers(map,begin,end,hdrs,extract_http_statusline,1);
}

void free_icap_http_state(icap_http_headers *hdrs){
	if(hdrs){
#define HTTP_REQHDR(hdr,varname) Free(hdrs->varname);
#define HTTP_RESPHDR(hdr,varname) Free(hdrs->resp_##varname);
#define HTTP_HDR(hdr,varname) HTTP_REQHDR(hdr,varname) HTTP_RESPHDR(hdr,varname)
#include "http_headers.h"
#undef HTTP_REQHDR
#undef HTTP_RESPHDR
#undef HTTP_HDR
		Free(hdrs->original_statusline);
		Free(hdrs->httpresver);
		Free(hdrs->statuscode);
		Free(hdrs->exposition);
		Free(hdrs->original_startline);
		Free(hdrs->method);
		Free(hdrs->rawuri);
		Free(hdrs->httpver);
		Free(hdrs->server);
		Free(hdrs->resp_server);
		Free(hdrs->new_startline);
		memset(hdrs,0,sizeof(*hdrs));
	}
}

int init_http_hdrscratch(icap_encapsulates *encap){
	size_t validlen;

	validlen = encap->reqhdr_len + encap->reshdr_len;
	// The length either must be zero, or the headers must end with a CRLF.
	// We eliminate all kinds of special cases by trimming the CRLF here.
	// The allocated buffer is thus actually two bytes longer than stored. 
	if(validlen){
		if((validlen < sizeof(CRLF) - 1) ||
			memcmp(CRLF,oqueue_const_ptrto(encap->hdrs,oqueue_usedlen(encap->hdrs) - (sizeof(CRLF) - 1)),sizeof(CRLF) - 1)){
			bitch("Headers don't end in CRLF\n");
			return -1;
		}
		validlen -= (sizeof(CRLF) - 1);
		oqueue_dec_usedlen(encap->hdrs,sizeof(CRLF) - 1);
	}
	if(hdrscratch_set_valid(&encap->http.startword,validlen)){
		return -1;
	}
	if(hdrscratch_set_skip(&encap->http.startword,0)){
		return -1;
	}
	return 0;
}

int init_icap_http(void){
	typeof(*http_cb_maps) *cur;

	if((hdrlrupat = create_lrupat(NULL)) == NULL){
		return -1;
	}
	for(cur = http_cb_maps ; cur->header ; ++cur){
		if(add_lrupat_nocase(hdrlrupat,cur->header,cur)){
			destroy_lrupat(hdrlrupat);
			return -1;
		}
	}
	return 0;
}

int stop_icap_http(void){
	destroy_lrupat(hdrlrupat);
	hdrlrupat = NULL;
	return 0;
}
