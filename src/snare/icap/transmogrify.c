#include <ctype.h>
#include <snare/oqueue.h>
#include <snare/icap/stats.h>
#include <snare/icap/request.h>
#include <libdank/utils/string.h>
#include <libdank/utils/rfc2396.h>
#include <libdank/utils/memlimit.h>
#include <snare/icap/transmogrify.h>

#define CRLF "\xd\xa"

static inline int
can_transmogrify(const icap_state *is){
	return !icap_state_txstartedp(is);
}

// Provided for the dynamic generation of redirects (snare's config only allows
// for a single, static redirect URI). Must be called before prepare_response()
// is called on the icap_state.
int rewrite_icap_http_startline(icap_state *is,const char *method,
			const uri *u,const char *httpver){
	ustring us = USTRING_INITIALIZER;

	if(stringize_uri(&us,u) < 0){
		reset_ustring(&us);
		return -1;
	}
	if(rewrite_icap_http_startline_flaturi(is,method,us.string,httpver)){
		reset_ustring(&us);
		return -1;
	}
	reset_ustring(&us);
	return 0;
}

int rewrite_icap_http_startline_flaturi(icap_state *is,const char *method,
			const char *uristr,const char *httpver){
	ustring u = USTRING_INITIALIZER;

	if(printUString(&u,"%s %s %s"CRLF,method,uristr,httpver) < 0){
		reset_ustring(&u);
		return -1;
	}
	if(rewrite_icap_http_startline_str(is,u.string)){
		reset_ustring(&u);
		return -1;
	}
	reset_ustring(&u);
	return 0;
}

int rewrite_icap_http_startline_str(icap_state *is,const char *u){
	char *newu;

	if(is->method != ICAP_METHOD_REQMOD){
		bitch("Can't rewrite startline on non-REQMOD\n");
		return -1;
	}
	if(!can_transmogrify(is)){
		bitch("Can't rewrite startline\n");
		return -1;
	}
	if((newu = Strdup(u)) == NULL){
		return -1;
	}
	// if we've already replaced once, startword and the initial scratchbuf
	// are already properly initialized; they only depend on the remainder.
	if(is->encaps.http.new_startline){
		Free(is->encaps.http.new_startline);
	}else if(hdrscratch_get_valid(&is->encaps.http.startword)){
		hdrscratch *hs;

		hs = hdrscratch_at(oqueue_ptrto(is->encaps.hdrs,0),0);
		if(hdrscratch_set_valid(hs,hdrscratch_get_valid(&is->encaps.http.startword)
					- is->encaps.http.startlinelen)){
			return -1;
		}
		if(hdrscratch_set_valid(&is->encaps.http.startword,0)){
			return -1;
		}
		if(hdrscratch_set_skip(hs,is->encaps.http.startlinelen)){
			return -1;
		}
		nag("Wrote skip/valid: %u / %u\n",hdrscratch_get_skip(hs),hdrscratch_get_valid(hs));
		icap_state_setmodified(is);
	}
	is->encaps.reqhdr_len -= is->encaps.http.startlinelen;
	is->encaps.http.startlinelen = strlen(u);
	is->encaps.reqhdr_len += is->encaps.http.startlinelen;
	is->encaps.http.new_startline = newu;
	return 0;
}

// Whenever we delete a section, we must update the preceeding skipbuf (if
// there is no preceeding skipbuf, we modify the startword). The new skipbuf
// (newsb) is initialized using the skiplen passed, assuming a validlen. absoff
// is relative to the buffer, thus the following identities (define reloff as
// reloff = absoff - ((char *)prior - buf)) on entry:
//
// 	absoff = (char *)prior - buf
// 	reloff < prior->valid + prior->skip
// 	reloff + skiplen <= prior->valid + prior->skip
//
//  a) Determine whether the new skipbuf will extend one (oldsb) to the right
//      (prior->valid + prior->skip == reloff + skiplen). In this case, look up
//      oldsb and: newsb->skip += oldsb->skip, newsb->valid = oldsb->valid.
//  b) Determine whether the new skipbuf needs be written, as opposed to
//      extending the prior (reloff + skiplen < prior->valid + prior->skip),
//      if so: prior->valid = reloff - prior->skip
//      otherwise: prior->skip += newsb->skip;
static int
splice_out_skipbuf(char *buf,hdrscratch **prior,size_t absoff,size_t skiplen,int terminal){
	hdrscratch *newsb = (hdrscratch *)(buf + absoff);
	size_t reloff;

	/* if(terminal){
		nag("TERMINAL! *******************\n");
	} */
	// Protect against attempts at removing a header so short that it can't
	// support a skipbuf (this shouldn't really happen; see http.h).
	if(skiplen < HDRSCRATCH_FIELD_BITS * 2 / CHAR_BIT){
		bitch("Can't remove a header of less than %db!\n",HDRSCRATCH_FIELD_BITS * 2 / CHAR_BIT);
		return -1;
	}
	// Only the startword can have a 0-length skip. Exploit this, since it
	// is impossible otherwise to calculate a meaningful relative offset.
	if(hdrscratch_get_skip(*prior) == 0){
		reloff = absoff;
	}else{
		reloff = absoff - ((const char *)*prior - buf);
	}
	// nag("RELOFF: %zu absoff: %zu priorskip: %u\n",reloff,absoff,hdrscratch_get_skip(*prior));
	if(reloff == hdrscratch_get_skip(*prior)){
		// nag("Extending previous skipbuf\n");
		if(hdrscratch_set_skip(*prior,hdrscratch_get_skip(*prior) + skiplen)){
			return -1;
		}
		if(hdrscratch_set_valid(*prior,hdrscratch_get_valid(*prior) - skiplen)){
			return -1;
		}
		newsb = *prior;
		/* nag("sprior %u vprior %u\n",
				hdrscratch_get_skip(*prior),
				hdrscratch_get_valid(*prior)); */
	}else{
		// nag("newsb - buf = %tu\n",(const char *)newsb - buf);
		if(hdrscratch_set_skip(newsb,skiplen)){
			return -1;
		}
		if(hdrscratch_set_valid(newsb,hdrscratch_get_valid(*prior) + hdrscratch_get_skip(*prior)
						- skiplen - reloff)){
			return -1;
		}
		// nag("Shrinking previous validbuf\n");
		if(hdrscratch_set_valid(*prior,reloff - hdrscratch_get_skip(*prior))){
			return -1;
		}
		/* nag("snew %u vnew %u\n",
				hdrscratch_get_skip(newsb),
				hdrscratch_get_valid(newsb)); */
	}
	if(!terminal && hdrscratch_get_valid(*prior) + hdrscratch_get_skip(*prior) == reloff + skiplen){
		hdrscratch *oldsb = (hdrscratch *)((char *)newsb + hdrscratch_get_skip(*prior));

		/* nag("prior - buf = %tu\n",(const char *)*prior - buf);
		nag("oldsb - buf = %tu oldsb - prior = %tu\n",
				(const char *)oldsb - buf,
				(const char *)oldsb - (const char *)*prior);
		nag("Subsuming successor hdrscratch: pskip %u pvalid %u\n",
				hdrscratch_get_skip(*prior),
				hdrscratch_get_valid(*prior));
		nag("snew %u vnew %u sold %u vold %u\n",
				hdrscratch_get_skip(newsb),
				hdrscratch_get_valid(newsb),
				hdrscratch_get_skip(oldsb),
				hdrscratch_get_valid(oldsb)); */
		if(hdrscratch_set_skip(newsb,hdrscratch_get_skip(newsb) +
						hdrscratch_get_skip(oldsb))){
			return -1;
		}
		if(hdrscratch_set_valid(newsb,hdrscratch_get_valid(oldsb))){
			return -1;
		}
	}
	*prior = newsb;
	return 0;
}

// buf is the beginning of the buffer (okey->buf), not the beginning of the
// validbuf! off is the offset of the validbuf relative to buf, and len is its
// length (this is the area that will be searched). prior is the prior skipbuf,
// or NULL if there was none (ie, we're searching the startword) -- this will
// need to be modified if the header sought leads the validbuf's contents.
static int
scrub_http_header_validbuf(char * const buf,size_t off,size_t len,hdrscratch *prior,
				const char *hdr,size_t hdrlen,size_t minoff){
	int removed = 0;
	size_t mapleft;
	char *mapcur;

	// nag("Looking at [%.*s]\n",(int)len,buf + off);
	mapcur = buf + off;
	mapleft = len;
	// FIXME this is inexecrable! replace with a patricia trie.
	while(mapleft){
		char *start;
		int crlf = 0;

		// nag("Looping on [%.*s]\n",(int)mapleft,mapcur);
		if(isspace(*(unsigned char *)mapcur)){
			++mapcur;
			--mapleft;
			continue;
		}
		// mappos is not whitespace, and there is at least 1 character
		start = mapcur++;
		// start is non-whitepsace. mappos is unknown. 0 chars possible
		while(--mapleft){
			if(crlf && *mapcur == CRLF[1]){
				++mapcur;
				--mapleft;
				crlf = 2;
				break;
			}
			crlf = 0;
			if(*mapcur == CRLF[0]){
				crlf = 1;
			}
			++mapcur; // mapleft is decremented in loopcond
		}
		if((size_t)(mapcur - start) >= hdrlen){
			if((size_t)(start - buf) >= minoff){
				if(strncasecmp(hdr,start,hdrlen) == 0){
					nag("Purging %tub header %.*s at %tu\n",mapcur - start,
						(int)(mapcur - start - crlf),start,start - buf);
					// nag("Removing [%.*s] (%zu@%zu)\n",(int)(mapcur - start),start,mapcur - start,start - buf);
					if(splice_out_skipbuf(buf,&prior,start - buf,mapcur - start,!mapleft)){
						return -1;
					}
					removed += mapcur - start;
					// might have more than one occurance; no break
				}
			}
		}
	}
	return removed;
}

static int
scrub_http_header(icap_encapsulates *encaps,const char *hdr,size_t hdrlen,size_t minoff){
	hdrscratch *prior = &encaps->http.startword;
	struct oqueue_key *okey = encaps->hdrs;
	size_t stripe,hdroff = 0;
	int removed = 0,r;

	// We must only look at validbufs. Otherwise, a random skipbuf could be
	// interpreted as a header, causing untold misery.
	if( (stripe = hdrscratch_get_valid(prior)) ){
		// nag("Searching %zu stripe\n",stripe);
		if((r = scrub_http_header_validbuf(oqueue_ptrto(okey,0),0,stripe,prior,hdr,hdrlen,minoff)) < 0){
			return -1;
		}
		removed += r;
		hdroff += hdrscratch_get_valid(prior);
	}
	while(hdroff < oqueue_usedlen(encaps->hdrs)){
		prior = hdrscratch_at(oqueue_ptrto(okey,0),hdroff);
		// nag("Skipping %zu stripe\n",prior->skip);
		hdroff += hdrscratch_get_skip(prior);
		if(hdroff >= oqueue_usedlen(encaps->hdrs)){
			break;
		}
		// nag("Searching %u stripe\n",hdrscratch_get_valid(prior));
		if((r = scrub_http_header_validbuf(oqueue_ptrto(okey,0),hdroff,hdrscratch_get_valid(prior),
					prior,hdr,hdrlen,minoff)) < 0){
			return -1;
		}
		removed += r;
		hdroff += hdrscratch_get_valid(prior);
	}
	return removed;
}

// Returns 0 on either successful elimination of the header or lack of the
// header in the first place; non-zero is reserved for runtime errors.
static int
remove_icap_http_header(icap_state *is,const char *hdr){
	size_t hdrlen = strlen(hdr);
	struct oqueue_key *oq;
	int removed;

	if(!can_transmogrify(is)){
		bitch("Can't remove %s\n",hdr);
		return -1;
	}
	if(hdr[hdrlen - 1] != ':'){
		bitch("Invalid header: %s\n",hdr);
		return -1;
	}
	if((oq = is->encaps.hdrs) == NULL){
		return 0;
	}
	// In HTTP responses, we only remove response headers. In requests, we
	// only remove request headers. We thus need pass a minimum and maximum
	// offset. Our maximum offset, however, will always be the buflen (as
	// we're always removing from the latter headers), and our minimum
	// offset will either be 0 (request) or the original reqhdr len
	// (response). Now, reqhdr_len is updated with deletions/additions, so
	// we can't use that...except, in the only case where we need it
	// (response), we don't delete or add request headers! Thus, it's sure
	// to be unmodified and thus accurate for our needs. So, we end up
	// needing no extra state whatsoever, and pass only minoff. w00t!
	if(is->encaps.reshdr_len){
		if((removed = scrub_http_header(&is->encaps,hdr,hdrlen,is->encaps.reqhdr_len)) < 0){
			return -1;
		}
		is->encaps.reshdr_len -= removed;
	}else if(is->encaps.reqhdr_len && is->encaps.bodytype != ICAP_ENCAPSULATE_BODY_RESPONSE){
		if((removed = scrub_http_header(&is->encaps,hdr,hdrlen,0)) < 0){
			return -1;
		}
		is->encaps.reqhdr_len -= removed;
	}
	return 0;
}

static inline hdrscratch *
get_last_hdrscratch(hdrscratch *startword,void *buf,size_t buflen){
	hdrscratch *prior = startword;
	size_t stripe,hdroff = 0;

	// nag("hdrscratch: %p valid: %u skip: %u hdroff %zu buflen %zu\n",prior,hdrscratch_get_valid(prior),hdrscratch_get_skip(prior),hdroff,buflen);
	if( (stripe = hdrscratch_get_valid(prior)) ){
		hdroff += stripe;
	}
	while(hdroff < buflen){
		prior = hdrscratch_at(buf,hdroff);
		// nag("hdrscratch: %p valid: %u skip: %u hdroff %zu buflen %zu\n",prior,hdrscratch_get_valid(prior),hdrscratch_get_skip(prior),hdroff,buflen);
		hdroff += hdrscratch_get_skip(prior);
		if(hdroff >= buflen){
			break;
		}
		hdroff += hdrscratch_get_valid(prior);
		// nag("hdrscratch: %p valid: %u skip: %u hdroff %zu buflen %zu\n",prior,hdrscratch_get_valid(prior),hdrscratch_get_skip(prior),hdroff,buflen);
	}
	return prior;
}

// Adding a preexisting header is supported by snare just fine; whether or not
// other HTTP entities will support it, however, is a question to everyone...
int add_icap_http_header(icap_state *is,const char *hdr,const char *value){
	icap_encapsulates *encaps = &is->encaps;
	hdrscratch *lastscratch;
	int added;

	if(!can_transmogrify(is)){
		bitch("Can't remove %s\n",hdr);
		return -1;
	}
	if(hdr == NULL || value == NULL){
		bitch("Need a header and value to operate on\n");
		return -1;
	}
	nag("Adding HTTP header %s %s\n",hdr,value);
	if((added = printf_icap_encapsulate(encaps->hdrs,"%s %s"CRLF,hdr,value)) < 0){
		return -1;
	}
	// We can't get the lastscratch referenced prior to printing, or else
	// the buffer might move, invalidating it. Likewise, we can't get the
	// lastscratch using the buflen following the print, or it is invalid.
	lastscratch = get_last_hdrscratch(&is->encaps.http.startword,
			oqueue_ptrto(encaps->hdrs,0),oqueue_usedlen(encaps->hdrs) - added);
	if(hdrscratch_set_valid(lastscratch,hdrscratch_get_valid(lastscratch) + added)){
		return -1;
	}
	icap_state_setmodified(is);
	if(is->encaps.bodytype == ICAP_ENCAPSULATE_BODY_RESPONSE ||
			is->method == ICAP_METHOD_RESPMOD){
		is->encaps.reshdr_len += added;
	}else{
		is->encaps.reqhdr_len += added;
	}
	return 0;
}

// Rewrite the HTTP headers with the provided content. If the header is
// present, it will be modified, usually requiring deletion followed by
// concatenation to the end of the headers. If it is not present, it will be
// added (if value is non-NULL -- that is, a NULL value deletes the header).
int rewrite_icap_http_header(icap_state *is,const char *hdr,const char *value){
	if(hdr == NULL){
		bitch("Need a header to operate on\n");
		return -1;
	}
	if(remove_icap_http_header(is,hdr)){
		return -1;
	}
	// FIXME don't say it's modified unless we actually removed something!
	icap_state_setmodified(is);
	if(value){
		if(add_icap_http_header(is,hdr,value)){
			return -1;
		}
	}
	return 0;
}

int rewritefmt_icap_http_header(icap_state *is,const char *hdr,const char *fmt,...){
	ustring us = USTRING_INITIALIZER;
	int ret = -1;
	va_list ap;

	va_start(ap, fmt);
	if(vprintUString(&us,fmt,ap) > 0){
		ret = rewrite_icap_http_header(is, hdr, us.string);
	}
	va_end(ap);
	reset_ustring(&us);
	return ret;
}

// Common initial steps of a rewrite:
//  a) check that transmogrification is allowed for the icap_state
//  b) initialize the new http header structure
//  c) parse and prepare the provided headers, using the appropriate callback
//  d) if we haven't received the last chunk, set up a drain
static int
setup_rewrite_drain(icap_state *is,httphdr_parsefxn parser,const char *headbuf,
			size_t headlen,icap_http_headers *newhttphdrs){
	if(!can_transmogrify(is)){
		bitch("Invalid state (0x%x) for rewrite\n",is->statevec);
		inc_stateexceptions();
		return -1;
	}
	memset(newhttphdrs,0,sizeof(*newhttphdrs));
	if(parser(headbuf,0,headlen,newhttphdrs)){
		bitch("Attempted to rewrite with invalid HTTP headers\n");
		return -1;
	}
	if(!icap_state_gotlastchunkp(is)){
		if((is->encaps.drainbody = create_icap_encapsulate(NULL)) == NULL){
			free_icap_http_state(newhttphdrs);
			return -1;
		}
		if(drain_pollinbuf(is->pibuf,icap_drain_chunkline,icap_drain_chunkdata)){
			orphan_icap_encapsulate(&is->encaps.drainbody);
			free_icap_http_state(newhttphdrs);
			return -1;
		}
	}
	return 0;
}

static int
rewrite_headers(icap_state *is,const char *headbuf,size_t headlen,
		size_t *lenset,size_t *lenreset,icap_http_headers *newhdrs){
	struct oqueue_key *headkey;

	free_icap_http_state(&is->encaps.http);
	is->encaps.http = *newhdrs;
	if(is->encaps.hdrs){
		if(rewriten_icap_encapsulate(is->encaps.hdrs,headbuf,headlen)){
			return -1;
		}
	}else if((headkey = create_icap_encapsulate(NULL)) == NULL){
		return -1;
	}else if(writen_icap_encapsulate(headkey,headbuf,headlen)){
		free_icap_encapsulate(&headkey);
		return -1;
	}else{
		is->encaps.hdrs = headkey;
	}
	*lenset = headlen;
	*lenreset = 0;
	if(init_http_hdrscratch(&is->encaps)){
		return -1;
	}
	return 0;
}

// The headers ought now have been replaced, and all state associated with them
// reinitialized. Move on to the body.
static int
rewrite_body(icap_state *is,const char *bodybuf,size_t bodylen,
		icap_encapsulate_types bodytype){
	struct oqueue_key *bodykey;

	if(bodylen){
		if(is->encaps.body){
			if(rewriten_icap_encapsulate(is->encaps.body,bodybuf,bodylen)){
				return -1;
			}
		}else if((bodykey = create_icap_encapsulate(NULL)) == NULL){
			return -1;
		}else if(writen_icap_encapsulate(bodykey,bodybuf,bodylen)){
			free_icap_encapsulate(&bodykey);
			return -1;
		}else{
			is->encaps.body = bodykey;
		}
		is->encaps.bodytype = bodytype;
	}else{
		if(is->encaps.body){
			if(orphan_icap_encapsulate(&is->encaps.body)){
				return -1;
			}
		}
		is->encaps.bodytype = ICAP_ENCAPSULATE_BODY_NULL;
	}
	is->encaps.body_tx_off = is->encaps.body_tx_len = 0;
	icap_state_settxtranscoded(is,0);
	icap_state_setcbtranscoded(is,0);
	if(is->encaps.transbody){
		if(orphan_icap_encapsulate(&is->encaps.transbody)){
			return -1;
		}
	}
	orphangzip_state(is);
	return 0;
}

// Perform a rewrite, but not a response -- leave it as an outgoing request.
int icap_request_rewrite(icap_state *is,const char *headbuf,size_t headlen,
				const char *bodybuf,size_t bodylen){
	icap_http_headers newhttphdrs;

	if(is->method != ICAP_METHOD_REQMOD){
		bitch("Can't rewrite request on non-REQMOD\n");
		inc_stateexceptions();
		return -1;
	}
	if(setup_rewrite_drain(is,postparse_http_reqhdr,headbuf,headlen,
					&newhttphdrs)){
		return -1;
	}
	nag("Rewriting with %zub/%zub\n",headlen,bodylen);
	icap_state_setrewritten(is);
	if(rewrite_headers(is,headbuf,headlen,&is->encaps.reqhdr_len,
				&is->encaps.reshdr_len,&newhttphdrs)){
		return -1;
	}
	if(rewrite_body(is,bodybuf,bodylen,ICAP_ENCAPSULATE_BODY_REQUEST)){
		return -1;
	}
	return 0;
}

// Rewrite as response -- can be used with either REQMOD (Request-Satisfaction)
// or RESPMOD (Reply-Modification). Accepts a header and a body buffer, of
// content type ctype. Upon a failure, the icap_state must be considered
// unusable for anything except sending an ICAP exception. The header buffer
// must be valid HTTP response headers, including a status line -- it will be
// checked with postparse_http_reshdr().
int icap_response_rewrite(icap_state *is,const char *headbuf,size_t headlen,
				const char *bodybuf,size_t bodylen){
	icap_http_headers newhttphdrs;

	if(setup_rewrite_drain(is,postparse_http_reshdr,headbuf,headlen,
					&newhttphdrs)){
		return -1;
	}
	nag("Rewriting with %zub/%zub\n",headlen,bodylen);
	icap_state_setrewritten(is);
	if(rewrite_headers(is,headbuf,headlen,&is->encaps.reshdr_len,
			       	&is->encaps.reqhdr_len,&newhttphdrs)){
		return -1;
	}
	if(rewrite_body(is,bodybuf,bodylen,ICAP_ENCAPSULATE_BODY_RESPONSE)){
		return -1;
	}
	return 0;
}

int icap_trickle_payload(icap_state *is,size_t tricklethrough){
	if(icap_state_verdictp(is)){
		bitch("%zu trickle following final verdict\n",tricklethrough);
		return -1;
	}
	if(tricklethrough < is->encaps.body_tx_len){
		bitch("Runt trickle %zu < %zu\n",tricklethrough,is->encaps.body_tx_len);
		return -1;
	}
	// nag("Trickling through %zu (was %zu)\n",tricklethrough,is->encaps.body_tx_len);
	is->encaps.body_tx_len = tricklethrough;
	return 0;
}
