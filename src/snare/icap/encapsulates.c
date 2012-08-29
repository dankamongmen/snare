#include <stddef.h>
#include <sys/poll.h>
#include <snare/oqueue.h>
#include <snare/server.h>
#include <snare/pollinbuf.h>
#include <snare/icap/http.h>
#include <snare/icap/stats.h>
#include <libdank/utils/fds.h>
#include <libdank/utils/text.h>
#include <snare/icap/request.h>
#include <snare/icap/response.h>
#include <libdank/utils/parse.h>
#include <libdank/utils/string.h>
#include <snare/icap/compression.h>
#include <libdank/objects/lexers.h>
#include <libdank/utils/memlimit.h>
#include <snare/icap/encapsulates.h>
#include <libdank/objects/crlfreader.h>

static unsigned
outstanding_verdicts(const icap_encapsulates *encap){
	unsigned ret = 0;

	if(encap->hdrs){
		ret += encap->hdrs->refcount - 1;
	}
	if(encap->body){
		ret += encap->body->refcount - 1;
	}
	if(encap->transbody){
		ret += encap->transbody->refcount - 1;
	}
	return ret;
}

// Represents the final RX of the request/response pair.
//
// NOTA BENE: DO NOT READ FURTHER REQUEST DATA UNTIL THE RESPONSE HAS BEEN SENT
// 
// We could go beyond this, beginning to read and process (but not respond to)
// the next request, while waiting for a verdict. To do this in our callback
// scheme, we'd either need to add request buffering to our ICAP state, or
// disable RX callbacks while continuing to RX, and then call pfd->rxfxn(pfd)
// manually from icap_tx_callback_complete(). This latter would be fine, except
// that it allows a client to fatally DoS us under extreme load due to a
// potentially massive corecursion as many requests' worth of data is
// unbuffered.
//
// Now, this does mean that if a client was to emit pipelined requests, we
// could have the start of one buffered simply due to a request being smaller
// than the RX buffer. Thus, the connection would enter livelock unless the
// client were to suddenly start TXing again (or was continuing to), thus
// setting POLLIN for its descriptor. Well, fuck you buddy! Next time, comply
// with RFC 3507.
static int
encapsulates_done(struct pollfd_state *pfd){
	icap_state *is = get_pfd_icap(pfd);

	nag("Encapsulates done for %d\n",pfd->pfd.fd);
	is->encaps.chunklen_current = 0;
	if(!icap_state_verdictp(is)){
		struct oqueue_key *okey;

		if(icap_state_cbtranscoded(is)){
			okey = is->encaps.transbody;
		}else{
			okey = is->encaps.body;
		}
		if(okey){
			inc_oqueue_bodies();
			if(queue_icap_encapsulate(okey,pfd,ICAP_CALLBACK_BODY,0)){
				return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
			}
		}
		// We might have just had a verdict, so we need check that
		// again. Furthermore, we might be anticipating verdicts, in
		// which case we don't want to preempt. Otherwise, there will
		// be no verdict, and we must issue one (this often happens for
		// RESPMODs without bodies).
		if(!outstanding_verdicts(&is->encaps) && !icap_state_verdictp(is)){
			// nag("no outstanding verdicts, marking %d done\n",pfd->pfd.fd);
			inc_noverdict();
			if(icap_callback(pfd,VERDICT_DONE,0)){
				return -1;
			}
		}
	}
	// There's nothing in our TX queue, and RX is still enabled. Move
	// directly to the next request...what if an exception (status >= 400)
	// is queued, though? We don't use else if because the
	// queue_icap_encapsulate() call could have invalidated is->iomode.
	if(icap_state_txdonep(is)){
		time_icap_session(is->method,&is->transstart);
		inc_method_ok(&is->method);
		if(reset_icap_state(is)){
			return -1;
		}
		return 0;
	}
	// Otherwise, disable rx for now
	icap_state_setrxdisabled(is);
	if(use_finaccept_mode(is->pibuf)){
		return -1;
	}
	return 0;
}

static const struct {
	const char *str;
	icap_encapsulate_types ienum;
} maps[] = {
	#define DECLARE_ENCAPSULATE(keystr,key)	\
	 {	.str = keystr,			\
		.ienum = key,			\
	 }
	DECLARE_ENCAPSULATE("req-hdr",ICAP_ENCAPSULATE_HDR_REQUEST),
	DECLARE_ENCAPSULATE("res-hdr",ICAP_ENCAPSULATE_HDR_RESPONSE),
	DECLARE_ENCAPSULATE("req-body",ICAP_ENCAPSULATE_BODY_REQUEST),
	DECLARE_ENCAPSULATE("res-body",ICAP_ENCAPSULATE_BODY_RESPONSE),
	DECLARE_ENCAPSULATE("opt-body",ICAP_ENCAPSULATE_BODY_OPTIONS),
	DECLARE_ENCAPSULATE("null-body",ICAP_ENCAPSULATE_BODY_NULL),
	DECLARE_ENCAPSULATE(NULL,ICAP_ENCAPSULATE_COUNT),
	#undef DECLARE_ENCAPSULATE
};

static icap_encapsulate_types
lex_encaptype(const char *token){
	const typeof(*maps) *cur;

	for(cur = maps ; cur->str ; ++cur){
		if(strcmp(token,cur->str) == 0){
			break;
		}
	}
	return cur->ienum;
}

void init_icap_encapsulates(icap_encapsulates *encap){
	memset(encap,0,sizeof(*encap));
	encap->bodytype = ICAP_ENCAPSULATE_BODY_NULL;
	// See icap_state_rxdisabledp(). We test for a 0 chunk having been
	// "read" (this is explicitly set in encapsulates_done() for no body).
	encap->chunklen_current = ~0UL;
}

int free_icap_encapsulates(icap_encapsulates *encap){
	int ret = 0;

	free_icap_http_state(&encap->http);
	ret |= orphan_icap_encapsulate(&encap->body);
	ret |= orphan_icap_encapsulate(&encap->hdrs);
	ret |= orphan_icap_encapsulate(&encap->drainbody);
	ret |= orphan_icap_encapsulate(&encap->transbody);
	return ret;
}

/* RFC 2616 3.6.1 Chunked Transfer Coding

   The chunked encoding modifies the body of a message in order to
   transfer it as a series of chunks, each with its own size indicator,
   followed by an OPTIONAL trailer containing entity-header fields. This
   allows dynamically produced content to be transferred along with the
   information necessary for the recipient to verify that it has
   received the full message.

       Chunked-Body   = *chunk
                        last-chunk
                        trailer
                        CRLF

       chunk          = chunk-size [ chunk-extension ] CRLF
                        chunk-data CRLF
       chunk-size     = 1*HEX
       last-chunk     = 1*("0") [ chunk-extension ] CRLF

       chunk-extension= *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
       chunk-ext-name = token
       chunk-ext-val  = token | quoted-string
       chunk-data     = chunk-size(OCTET)
       trailer        = *(entity-header CRLF)

   The chunk-size field is a string of hex digits indicating the size of
   the chunk. The chunked encoding is ended by any chunk whose size is
   zero, followed by the trailer, which is terminated by an empty line.

   The trailer allows the sender to include additional HTTP header
   fields at the end of the message. The Trailer header field can be
   used to indicate which header fields are included in a trailer (see
   section 14.40).

   A server using chunked transfer-coding in a response MUST NOT use the
   trailer for any header fields unless at least one of the following is
   true:

   a)the request included a TE header field that indicates "trailers" is
     acceptable in the transfer-coding of the  response, as described in
     section 14.39; or,

   b)the server is the origin server for the response, the trailer
     fields consist entirely of optional metadata, and the recipient
     could use the message (in a manner acceptable to the origin server)
     without receiving this metadata.  In other words, the origin server
     is willing to accept the possibility that the trailer fields might
     be silently discarded along the path to the client.

   This requirement prevents an interoperability failure when the
   message is being received by an HTTP/1.1 (or later) proxy and
   forwarded to an HTTP/1.0 recipient. It avoids a situation where
   compliance with the protocol would have necessitated a possibly
   infinite buffer on the proxy.

   An example process for decoding a Chunked-Body is presented in
   appendix 19.4.6.

   All HTTP/1.1 applications MUST be able to receive and decode the
   "chunked" transfer-coding, and MUST ignore chunk-extension extensions
   they do not understand. */

static int
icap_want_trailer(struct pollfd_state *pfd,char *line){
	icap_state *is = get_pfd_icap(pfd);
	size_t linelen;

	if(strcmp(line,CRLF) == 0){ // end of trailers
		if(is->encaps.trailer_len){
			inc_trailers();
		}
		return encapsulates_done(pfd);
	}
	inc_trailer_lines();
	linelen = strlen(line);
	nag("Got trailer line, %zub\n",linelen);
	if(writen_icap_encapsulate(is->encaps.body,line,linelen)){
		return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
	}
	is->encaps.trailer_len += linelen;
	return 0;
}

static int
icap_drain_trailer(struct pollfd_state *pfd,char *line){
	icap_state *is = get_pfd_icap(pfd);

	if(strcmp(line,CRLF) == 0){ // end of trailers
		if(is->encaps.trailer_len){
			inc_trailers();
		}
		return encapsulates_done(pfd);
	}
	inc_trailer_lines();
	nag("Drained trailer line on %d\n",pfd->pfd.fd);
	return 0;
}

static int icap_want_chunkline(struct pollfd_state *,char *);

static int
icap_drain_chunkcrlf(struct pollfd_state *pfd,char *line){
	icap_state *is = get_pfd_icap(pfd);

	if(strcmp(line,CRLF)){
		bitch("Expected CRLF to end chunk\n");
		return send_icapexception(pfd,ICAPSTATUS_BAD_REQUEST);
	}
	return use_crlf_mode(is->pibuf,icap_drain_chunkline);
}

static int
icap_want_chunkcrlf(struct pollfd_state *pfd,char *line){
	icap_state *is = get_pfd_icap(pfd);

	if(strcmp(line,CRLF)){
		bitch("Expected CRLF to end chunk\n");
		return send_icapexception(pfd,ICAPSTATUS_BAD_REQUEST);
	}
	return use_crlf_mode(is->pibuf,icap_want_chunkline);
}

int icap_drain_chunkdata(struct pollfd_state *pfd){
	icap_state *is = get_pfd_icap(pfd);

	return use_crlf_mode(is->pibuf,icap_drain_chunkcrlf);
}

// preconditions: iomode is one of INTROGRESSION or STREAMING
static int
icap_want_chunkdata(struct pollfd_state *pfd){
	icap_state *is = get_pfd_icap(pfd);
	struct oqueue_key *txkey,*cbkey;
	size_t txlen,cblen,txoff;
	
	cbkey = txkey = is->encaps.body;
	txoff = oqueue_usedlen(is->encaps.body);
	// Both the callback or the transfer might use either the transcoded or
	// the original data, due to our opportunistic compression and the
	// callback API's specifications. All three must be tracked (of chunk
	// length, transfer length and callback length), and transcoding might
	// set either callback length or transfer length to 0!
	cblen = txlen = is->encaps.chunklen_current;
	// nag("%zub chunk in state %s for %d\n",txlen,name_icap_iomode(is->iomode),pfd->pfd.fd);
	// We must make the state change prior to queue_icap_encapsulate(),
	// since it could cause us to enter the draining chain.
	if(is->encaps.chunklen_current){
		if(use_crlf_mode(is->pibuf,icap_want_chunkcrlf)){
			return -1;
		}
	}else{
		if(use_crlf_mode(is->pibuf,icap_want_trailer)){
			return -1;
		}
		// is->encaps.chunklen_current = ~0UL;
	}
	oqueue_inc_usedlen(is->encaps.body,txlen);
	if(icap_state_rxtranscode(is)){
		size_t translen;

		if(zlib_transform(is,txoff,txlen,&translen)){
			return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
		}
		if(icap_state_txtranscoded(is)){
			txkey = is->encaps.transbody;
			txlen = translen;
			txoff = oqueue_usedlen(is->encaps.transbody) - translen;
		}
		if(icap_state_cbtranscoded(is)){
			cbkey = is->encaps.transbody;
			cblen = translen;
		}
	}
	// If we've had a verdict, and it was a rewrite, we'll be on the drain
	// path rather than this one. If we've had a verdict otherwise, send
	// the data along immediately -- we're streaming.
	if(icap_state_verdictp(is)){
		// Transcoding might have taken our 0-chunk and turned it into
		// a non-0 chunk, or vice versa. If we got a 0-chunk, we need
		// write it either way, but only after the transcoded chunk (if
		// one has been generated). Hence the unintuitive conditions...
		if(txlen){
			// nag("Sending %zu (0x%zx)b...\n",txlen,txlen);
			if(send_icap_chunk(pfd,txkey,txoff,txlen,icap_state_gotlastchunkp(is))){
				return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
			}
		}else if(icap_state_gotlastchunkp(is)){
			if(send_icap_chunk(pfd,NULL,0,0,0)){
				return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
			}
		}
		// nag("Enqueued chunk, state %s\n",name_icap_iomode(is->iomode));
	}else if(cblen && txlen && !outstanding_verdicts(&is->encaps)){
		inc_oqueue_body_octets(cblen);
		inc_oqueue_bodies();
		if(queue_icap_encapsulate(cbkey,pfd,ICAP_CALLBACK_INCOMPLETE_BODY,txlen + txoff)){
			return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
		}
	}
	return 0;
}

static int
parse_icap_chunkline(char *line,icap_state *icap){
	uint64_t len;

	if(lex_u64_ashex((const char **)&line,&len)){
		return -1;
	}
	icap->encaps.chunklen_current = len;
	return 0;
}

int icap_drain_chunkline(struct pollfd_state *pfd,char *line){
	icap_state *is = get_pfd_icap(pfd);

	if(parse_icap_chunkline(line,is)){
		return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
	}
	// nag("%zub chunk for %d\n",is->encaps.chunklen_current,pfd->pfd.fd);
	if(is->encaps.chunklen_current){ // len == 0 on (empty) last chunk
		if(drainchunk_icap_encapsulate(is->encaps.drainbody,is->pibuf,
				is->encaps.chunklen_current,icap_drain_chunkdata)){
			return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
		}
	}else{
		nag("Drained body on %d\n",pfd->pfd.fd);
		// is->encaps.chunklen_current = ~0UL;
		return use_crlf_mode(is->pibuf,icap_drain_trailer);
	}
	return 0;
}

static int
icap_want_chunkline(struct pollfd_state *pfd,char *line){
	icap_state *is = get_pfd_icap(pfd);

	// nag("chunkline in state %s for %d\n",name_icap_iomode(is->iomode),pfd->pfd.fd);
	if(parse_icap_chunkline(line,is)){
		return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
	}
	if(is->encaps.chunklen_current){ // len == 0 on (empty) last chunk
		if(readchunk_icap_encapsulate(is->encaps.body,is->pibuf,
				is->encaps.chunklen_current,icap_want_chunkdata)){
			return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
		}
	}else{
		// nag("Read %zub body on %d, state %s\n",oqueue_usedlen(is->encaps.body),
		// 		pfd->pfd.fd,name_icap_iomode(is->iomode));
		if(icap_want_chunkdata(pfd)){
			return -1;
		}
	}
	return 0;
}

// All advertised headers have been read; if they were invalid, an exception was
// generated. No verdict can possibly have been issued, since handler callbacks
// only begin within this function; we can thus trust the encapsulate setup data
// as generated by begin_encapsulate_extraction() (ie, it cannot yet have been
// rewritten). It is impossible for any iomode other than INTROGRESSION to be
// set upon entry to this function, since only encapsulates_done() moves to
// IMPACTED and all other modes are post-verdict.
static int
headers_done(struct pollfd_state *pfd){
	icap_encapsulate_types orig_bodytype;
	icap_state *is = get_pfd_icap(pfd);

	orig_bodytype = is->encaps.bodytype;
	// nag("Headers are done in state %s for %d\n",name_icap_iomode(is->iomode),pfd->pfd.fd);
	if(init_http_hdrscratch(&is->encaps)){
		return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
	}
	// We don't need to set this if we exit via encapsulates_done() direct
	// call below (it'll be reinitialized to icap_want_startline()), but we 
	// can't unilaterally set it post-queue (we could have been moved to the
	// drain cycle via a rewrite))...
	if(use_crlf_mode(is->pibuf,icap_want_chunkline)){
		return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
	}
	if(is->encaps.hdrs){
		if(is->encaps.reqhdr_len){
			if(postparse_http_reqhdr(oqueue_ptrto(is->encaps.hdrs,0),0,is->encaps.reqhdr_len,&is->encaps.http)){
				// FIXME what if it's an internal error? pass value-res
				return send_icapexception(pfd,ICAPSTATUS_BAD_COMPOSITION);
			}
		}
		if(is->encaps.reshdr_len){
			if(postparse_http_reshdr(oqueue_ptrto(is->encaps.hdrs,0),is->encaps.reqhdr_len,is->encaps.reshdr_len,&is->encaps.http)){
				// FIXME what if it's an internal error? pass value-res
				return send_icapexception(pfd,ICAPSTATUS_BAD_COMPOSITION);
			}
		}
		inc_oqueue_headers();
		inc_oqueue_header_octets(oqueue_usedlen(is->encaps.hdrs));
		if(orig_bodytype == ICAP_ENCAPSULATE_BODY_RESPONSE){
			if(offergzip_response(is)){
				return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
			}
		}
		if(queue_icap_encapsulate(is->encaps.hdrs,pfd,ICAP_CALLBACK_HEADERS,0)){
			return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
		}
	}else{
		inc_no_httphdrs();
	}
	if(orig_bodytype == ICAP_ENCAPSULATE_BODY_NULL){
		// nag("No body was advertised on %d\n",pfd->pfd.fd);
		inc_no_httpbody();
		return encapsulates_done(pfd);
	}
	// We might have rewritten, in which case we're draining. That's the only
	// way we could already have a body (we might not, but in that case we
	// just don't need one at all).
	if(is->encaps.drainbody == NULL){
		if((is->encaps.body = create_icap_encapsulate(NULL)) == NULL){
			return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
		}
	}
	return 0;
}

/* RFC 3507, 4.4.1: The "Encapsulated" Header

   The offset of each encapsulated section's start relative to the start
   of the encapsulating message's body is noted using the "Encapsulated"
   header.  This header MUST be included in every ICAP message.  For
   example, the header

      Encapsulated: req-hdr=0, res-hdr=45, res-body=100

   indicates a message that encapsulates a group of request headers, a
   group of response headers, and then a response body.  Each of these
   is included at the byte-offsets listed.  The byte-offsets are in
   decimal notation for consistency with HTTP's Content-Length header.

   The special entity "null-body" indicates there is no encapsulated
   body in the ICAP message.

   The syntax of an Encapsulated header is:

   encapsulated_header: "Encapsulated: " encapsulated_list
   encapsulated_list: encapsulated_entity |
                      encapsulated_entity ", " encapsulated_list
   encapsulated_entity: reqhdr | reshdr | reqbody | resbody | optbody
   reqhdr  = "req-hdr" "=" (decimal integer)
   reshdr  = "res-hdr" "=" (decimal integer)
   reqbody = { "req-body" | "null-body" } "=" (decimal integer)
   resbody = { "res-body" | "null-body" } "=" (decimal integer)
   optbody = { "opt-body" | "null-body" } "=" (decimal integer)

   There are semantic restrictions on Encapsulated headers beyond the
   syntactic restrictions.  The order in which the encapsulated parts
   appear in the encapsulating message-body MUST be the same as the
   order in which the parts are named in the Encapsulated header.  In
   other words, the offsets listed in the Encapsulated line MUST be
   monotonically increasing.  In addition, the legal forms of the
   Encapsulated header depend on the method being used (REQMOD, RESPMOD,
   or OPTIONS).  Specifically:

   REQMOD  request  encapsulated_list: [reqhdr] reqbody
   REQMOD  response encapsulated_list: {[reqhdr] reqbody} |
                                       {[reshdr] resbody}
   RESPMOD request  encapsulated_list: [reqhdr] [reshdr] resbody
   RESPMOD response encapsulated_list: [reshdr] resbody
   OPTIONS response encapsulated_list: optbody

   In the above grammar, note that encapsulated headers are always
   optional.  At most one body per encapsulated message is allowed.  If
   no encapsulated body is presented, the "null-body" header is used
   instead; this is useful because it indicates the length of the header
   section.

   Examples of legal Encapsulated headers:

   REQMOD request: This encapsulated HTTP request's headers start at offset 0;
   the HTTP request body (e.g., in a POST) starts at 412.
   Encapsulated: req-hdr=0, req-body=412

   REQMOD request: Similar to the above, but no request body is present (e.g.,
   a GET).  We use the null-body directive instead. In both this case and the
   previous one, we can tell from the Encapsulated header that the request
   headers were 412 bytes long.
   Encapsulated: req-hdr=0, null-body=412

   REQMOD response: ICAP server returned a modified request, with body
   Encapsulated: req-hdr=0, req-body=512

   RESPMOD request: Request headers at 0, response headers at 822, response
   body at 1655.  Note that no request body is allowed in RESPMOD requests.
   Encapsulated: req-hdr=0, res-hdr=822, res-body=1655

   RESPMOD or REQMOD response: header and body returned
   Encapsulated: res-hdr=0, res-body=749

   OPTIONS response when there IS an options body
   Encapsulated: opt-body=0

   OPTIONS response when there IS NOT an options body
   Encapsulated: null-body=0 */

// The sum length of encapsulated text for any given ICAP message is determined
// by the presence and makeup of the Encapsulated: header (see ICAP Errata,
// "When to send an encapsulated header", at 
// http://www.measurement-factory.com/std/icap/#e1.)
static int
parse_encapsulated_header(char *encap,icap_encapsulates *encaps,icap_method method){
	icap_encapsulate_types lastitype = ICAP_ENCAPSULATE_COUNT;
	char *value,*token;

	// RFC 3507, 4.4.1 is quite definitive: a ", " separates items in an
	// encapsulation list. carve_value_pair() thus works, returning us
	// values of the form "uint," and "uint".
	while( (token = carve_value_pair(&encap,&value)) ){
		icap_encapsulate_types itype;
		uint32_t offset;

		if(*token == '\0'){
			break;
		}
		if((itype = lex_encaptype(token)) == ICAP_ENCAPSULATE_COUNT){
			bitch("Unknown encapsulate type: %s\n",token);
			return -1;
		}
		if(lex_u32((const char **)&value,&offset) < 0){
			return -1;
		}
		// nag("Got value of %u for %s (type %d)\n",offset,token,itype);
		if(lastitype == ICAP_ENCAPSULATE_COUNT){
			if(offset != 0){
				bitch("First type shouldn't send non-zero offset\n");
				return -1;
			}
		}else if(lastitype > itype){
			bitch("Received %s (%d) after %d\n",token,itype,lastitype);
			return -1;
		// this relies on the precise ordering of the enum, gross! it
		// checks that we have only one body type listed
		}else if(lastitype > ICAP_ENCAPSULATE_HDR_RESPONSE){
			bitch("Received %s (%d) after %d\n",token,itype,lastitype);
			return -1;
		}else if(lastitype == ICAP_ENCAPSULATE_HDR_REQUEST){
			encaps->reqhdr_len = offset;
		}else if(lastitype == ICAP_ENCAPSULATE_HDR_RESPONSE){
			encaps->reshdr_len = offset - encaps->reqhdr_len;
		}
		if((lastitype = itype) > ICAP_ENCAPSULATE_HDR_RESPONSE){
			encaps->bodytype = itype;
		}
		if(itype == ICAP_ENCAPSULATE_HDR_RESPONSE || itype == ICAP_ENCAPSULATE_BODY_RESPONSE){
			if(method != ICAP_METHOD_RESPMOD){
				bitch("Got reshdr / resbdy outside RESPMOD\n");
				return -1;
			}
		}else if(itype == ICAP_ENCAPSULATE_BODY_REQUEST){
			if(method != ICAP_METHOD_REQMOD){
				bitch("Got reqbdy outside REQMOD\n");
				return -1;
			}
		}else if(itype == ICAP_ENCAPSULATE_BODY_OPTIONS){
			if(method != ICAP_METHOD_OPTIONS){
				bitch("Got optbdy outside OPTIONS\n");
				return -1;
			}
		}
	}
	if(token == NULL){
		bitch("Parse error: %s\n",encap);
		return -1;
	}
	return 0;
}

static inline off_t
get_reqhdr_length(const icap_encapsulates *encaps){
	return encaps->reqhdr_len;
}

static inline off_t
get_reshdr_length(const icap_encapsulates *encaps){
	return encaps->reshdr_len;
}

#define NULLBODYDEF "null-body"
#define ENCAPHEADER "Encapsulated: "
int prepare_icap_empty_encapheader(int sd,writeq *wq){
	nag("Sending " ENCAPHEADER "%s=0 on %d\n",NULLBODYDEF,sd);
	return writeq_printf(wq,ENCAPHEADER "%s=0" CRLF,NULLBODYDEF);
}

int prepare_icap_encapheader(int sd,writeq *wq,const icap_encapsulates *encaps){
	const char *hdr = NULL,*body = NULL;
	off_t offset = 0,roffset = 0;
	int ret;

	if( (offset = get_reqhdr_length(encaps)) ){
		roffset = get_reshdr_length(encaps);
		hdr = "req-hdr";
	}else if( (offset = get_reshdr_length(encaps)) ){
		hdr = "res-hdr";
	}
	switch(encaps->bodytype){
		case ICAP_ENCAPSULATE_BODY_REQUEST:
			body = "req-body";
			break;
		case ICAP_ENCAPSULATE_BODY_RESPONSE:
			body = "res-body";
			break;
		case ICAP_ENCAPSULATE_BODY_OPTIONS:
			body = "opt-body";
			break;
		case ICAP_ENCAPSULATE_BODY_NULL:
		case ICAP_ENCAPSULATE_COUNT:
			body = NULLBODYDEF;
			break;
		default:
			nag("Unsupported body type: %d\n",encaps->bodytype);
			return -1;
	}
	if(roffset){
		nag("Sending %s=0, res-hdr=%lld, %s=%lld on %d\n",hdr,(long long)offset,body,(long long)(offset + roffset),sd);
		ret = writeq_printf(wq,ENCAPHEADER "%s=0, res-hdr=%lld, %s=%lld" CRLF,hdr,(long long)offset,body,(long long)(offset + roffset));
	}else if(hdr){
		nag("Sending %s=0, %s=%lld on %d\n",hdr,body,(long long)offset,sd);
		ret = writeq_printf(wq,ENCAPHEADER "%s=0, %s=%lld" CRLF,hdr,body,(long long)offset);
	}else{
		nag("Sending %s=0 on %d\n",body,sd);
		ret = writeq_printf(wq,ENCAPHEADER "%s=0" CRLF,body);
	}
	if(ret < 0){
		return -1;
	}
	return 0;
}
#undef ENCAPHEADER

static int
icap_want_reshdr(struct pollfd_state *pfd){
	icap_state *is = get_pfd_icap(pfd);

	// nag("Read %jdb response header\n",(uintmax_t)is->encaps.reshdr_len);
	oqueue_inc_usedlen(is->encaps.hdrs,is->encaps.reshdr_len);
	return headers_done(pfd);
}

static int
icap_want_reqhdr(struct pollfd_state *pfd){
	icap_state *is = get_pfd_icap(pfd);

	// nag("Read %jdb request header\n",(uintmax_t)is->encaps.reqhdr_len);
	oqueue_inc_usedlen(is->encaps.hdrs,is->encaps.reqhdr_len);
	if(is->encaps.reshdr_len){
		if(readchunk_icap_encapsulate(is->encaps.hdrs,is->pibuf,
					is->encaps.reshdr_len,icap_want_reshdr)){
			return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
		}
	}else{
		return headers_done(pfd);
	}
	return 0;
}

int begin_encapsulate_extraction(struct pollfd_state *pfd){
	icap_state *is = get_pfd_icap(pfd);

	// RFC 3507 Errata 1, "When to send an Encapsulated header" predicates
	// ICAP body presence on the header.
	if(is->headers.encapsulated){
		icap_encapsulates *encaps = &is->encaps;
		int ret;

		ret = parse_encapsulated_header(is->headers.encapsulated,
						encaps,is->method);
		// The parsing call was destructive; free things up.
		Free(is->headers.encapsulated);
		is->headers.encapsulated = NULL;
		if(ret < 0){
			return send_icapexception(pfd,ICAPSTATUS_BAD_REQUEST);
		}
		nag("reqlen: %zu reslen: %zu btype: %u on %d\n",encaps->reqhdr_len,
			encaps->reshdr_len,encaps->bodytype,pfd->pfd.fd);
	}
	if(is->encaps.reqhdr_len){
		if((is->encaps.hdrs = create_icap_encapsulate(NULL)) == NULL){
			return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
		}
		if(readchunk_icap_encapsulate(is->encaps.hdrs,is->pibuf,
					is->encaps.reqhdr_len,icap_want_reqhdr)){
			return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
		}
	}else if(is->encaps.reshdr_len){
		if((is->encaps.hdrs = create_icap_encapsulate(NULL)) == NULL){
			return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
		}
		if(readchunk_icap_encapsulate(is->encaps.hdrs,is->pibuf,
					is->encaps.reshdr_len,icap_want_reshdr)){
			return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
		}
	}else{
		return headers_done(pfd);
	}
	return 0;
}
