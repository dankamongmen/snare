#include <stdlib.h>
#include <sys/poll.h>
#include <snare/poller.h>
#include <snare/oqueue.h>
#include <snare/version.h>
#include <snare/threads.h>
#include <snare/pollinbuf.h>
#include <snare/icap/stats.h>
#include <snare/icap/request.h>
#include <snare/icap/response.h>
#include <libdank/utils/maxfds.h>
#include <libdank/utils/syswrap.h>
#include <libdank/utils/memlimit.h>
#include <libdank/objects/crlfreader.h>

// To be called whenever we successfully write everything enqueued, not just
// when we've finished the response -- this finalizes a TX burst, not all TX.
static int
icap_tx_finalize(struct pollfd_state *pfd){
	icap_state *is = get_pfd_icap(pfd);

	icap_state_settxallowed(is,1);
	// We'll get at least one early call due to edge-triggered event
	// polling and a desire to avoid adding/removing fd's (it's an extra
	// callback up front for savings over the life of the connection).
	if(is->status == 0){
		return 0;
	}
	time_icap_tx(is->method,&is->txstart);
	// If we're not done receiving, then RX hasn't been disabled. Return.
	// An ICAP exception would require aborting now, but it always moves us
	// to ICAP_IMPACTED for precisely this reason. We cannot be either of
	// ICAP_INTROGRESSION or ICAP_INGENUOUS on entry.
	if(!icap_state_rxdisabledp(is)){
		// nag("Sent data on %d (status %d); RX remains\n",
		//	pfd->pfd.fd,is->status);
		nag("Flushed %d (status %d)\n",pfd->pfd.fd,is->status);
		return 0;
	}
	if(is->encaps.body_tx_len){
		return 0;
	}
	nag("Flushed %d through %zu (status %d)\n",pfd->pfd.fd,
			is->encaps.body_tx_off,is->status);
	time_icap_session(is->method,&is->transstart); // The request has been served
	if(is->status >= ICAPSTATUS_BAD_REQUEST){
		inc_method_fail(&is->method);
		nag("Closing ICAP conn %d; sent error status (%d >= %d)\n",
			pfd->pfd.fd,is->status,ICAPSTATUS_BAD_REQUEST);
		return -1;
	}
	inc_method_ok(&is->method);
	// Sets crlf callback to state machine's start function
	if(reset_icap_state(is)){
		return -1;
	}
	return 0;
}

// The only valid TX callback for ICAP sockets. Writes everything enqueued to
// the writeq. If it manages to empty the writeq, returns to POLLIN. This is
// not to be directly called; it relies on poller callback semantics (for
// direct sending, simply call send_writeq_data(), on which this relies).
int icap_tx_callback(struct poller *p __attribute__ ((unused)),struct pollfd_state *pfd){
	icap_state *is = get_pfd_icap(pfd);
	writeq_res res;

	// Unless we start dynamically managing the tx event, check this so as
	// not to go through icap_tx_finalize() twice.
	if(writeq_emptyp(&is->wq)){
		return 0;
	}
	if((res = send_writeq_data(&is->wq,pfd->pfd.fd)) == WRITEQ_RES_SUCCESS){
		return icap_tx_finalize(pfd);
	}else if(res != WRITEQ_RES_NBLOCK){
		return -1;
	}
	// nag("Writing to %d would have blocked, returning 0\n",pfd->pfd.fd);
	return 0;
}

// Enqueue a chunk of tricklable data without affecting transmission status,
// and optionally include a zero-chunk.
static int
enqueue_icap_chunk(icap_state *is,struct oqueue_key *txkey,size_t txoff,
				size_t txlen,int pluszchunk){
	if(writeq_printf(&is->wq,"%zx" CRLF,txlen)){
		return -1;
	}
	if(writeq_sendfile(&is->wq,txkey,txoff,txlen)){
		return -1;
	}
	if(pluszchunk){
		// nag("writing zero chunk\n");
		if(writeq_printf(&is->wq,CRLF "0" CRLF CRLF)){
			return -1;
		}
	}else{
		// nag("not writing zero chunk\n");
		if(writeq_printf(&is->wq,CRLF)){
			return -1;
		}
	}
	return 0;
}

static int
prepare_icap_tx(struct pollfd_state *pfd){
	icap_state *is = get_pfd_icap(pfd);
	writeq_res res;

	if(is->status == 0){
		bitch("Can't send data without status\n");
		inc_stateexceptions();
	}
	Gettimeofday(&is->txstart,NULL);
	if((res = send_writeq_data(&is->wq,pfd->pfd.fd)) == WRITEQ_RES_SUCCESS){
		// nag("Completed TX in the fast path for %d\n",pfd->pfd.fd);
		return icap_tx_finalize(pfd);
	}else if(res == WRITEQ_RES_NBLOCK){
		icap_state_settxallowed(is,0);
		return 0;
	}
	return -1;
}

// The zero-chunk can be written via send_icap_chunk(is,NULL,0,0,0).
int send_icap_chunk(struct pollfd_state *pfd,struct oqueue_key *txkey,
				size_t txoff,size_t txlen,int pluszchunk){
	icap_state *is = get_pfd_icap(pfd);

	// nag("TX %zu (0x%zx)b at offset %zu on %d %s\n",
	//	txlen,txlen,txoff,pfd->pfd.fd,
	//	pluszchunk ? "pluszero" : "MF"); // more frags
	if(enqueue_icap_chunk(is,txkey,txoff,txlen,pluszchunk)){
		return -1;
	}
	if(icap_state_txallowedp(is)){
		if(prepare_icap_tx(pfd)){
			return -1;
		}
	}
	return 0;
}

// RFC 2616, 6.1 Status-Line: The first line of a Response message is the
// Status-Line, consisting of the protocol version followed by a numeric status
// code and its associated textual phrase, with each element separated by SP
// characters. No CR or LF is allowed except in the final CRLF sequence.
//
// Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
static int
prepare_icap_statusline(icap_state *icap,icap_status status){
	const char *phrase;

	if(icap->status){
		bitch("Using status %d, tried to set %d\n",icap->status,status);
		return -1;
	}
	icap->status = status;
	if((phrase = phrase_of_statcode(status)) == NULL){
		bitch("Unknown status code %d\n",status);
		inc_stateexceptions();
		return -1;
	}
	if(writeq_printf(&icap->wq,"ICAP/1.0 %d %s" CRLF,status,phrase)){
		return -1;
	}
	return 0;
}

/* From RFC 2616:

3.8 Product Tokens

Product tokens are used to allow communicating applications to identify
themselves by software name and version. Most fields using product tokens also
allow sub-products which form a significant part of the application to be
listed, separated by white space. By convention, the products are listed in
order of their significance for identifying the application.

       product         = token ["/" product-version]
       product-version = token

Examples:

       User-Agent: CERN-LineMode/2.15 libwww/2.17b3
       Server: Apache/0.8.4

Product tokens SHOULD be short and to the point. They MUST NOT be used for
advertising or other non-essential information. Although any token character
MAY appear in a product-version, this token SHOULD only be used for a version
identifier (i.e., successive versions of the same product SHOULD only differ in
the product-version portion of the product value). 

14.38 Server

The Server response-header field contains information about the software used
by the origin server to handle the request. The field can contain multiple
product tokens (section 3.8) and comments identifying the server and any
significant subproducts. The product tokens are listed in order of their
significance for identifying the application.

       Server         = "Server" ":" 1*( product | comment )

Example:

       Server: CERN/3.0 libwww/2.17

If the response is being forwarded through a proxy, the proxy application MUST
NOT modify the Server response-header. Instead, it SHOULD include a Via field
(as described in section 14.45).

      Note: Revealing the specific software version of the server might
      allow the server machine to become more vulnerable to attacks
      against software that is known to contain security holes. Server
      implementors are encouraged to make this field a configurable
      option. */

/* From RFC 3507, section 4.3.3 "Response Headers":

   ICAP's response-header fields allow the server to pass additional
   information in the response that cannot be placed in the ICAP's
   status line.

   A response-specific header is allowed in ICAP requests, following the
   same semantics as the corresponding HTTP response headers (Section
   6.2 of [RFC 2616]).  This is:

      Server (see Section 14.38 of [RFC 2616]) */

/* RFC 3507

4.7  ISTag Response Header

   The ISTag ("ICAP Service Tag") response-header field provides a way
   for ICAP servers to send a service-specific "cookie" to ICAP clients
   that represents a service's current state.  It is a 32-byte-maximum
   alphanumeric string of data (not including the null character) that
   may, for example, be a representation of the software version or
   configuration of a service.  An ISTag validates that previous ICAP
   server responses can still be considered fresh by an ICAP client that
   may be caching them.  If a change on the ICAP server invalidates
   previous responses, the ICAP server can invalidate portions of the
   ICAP client's cache by changing its ISTag.  The ISTag MUST be
   included in every ICAP response from an ICAP server.

   For example, consider a virus-scanning ICAP service.  The ISTag might
   be a combination of the virus scanner's software version and the
   release number of its virus signature database.  When the database is
   updated, the ISTag can be changed to invalidate all previous
   responses that had been certified as "clean" and cached with the old
   ISTag.

   ISTag is similar, but not identical, to the HTTP ETag.  While an ETag
   is a validator for a particular entity (object), an ISTag validates
   all entities generated by a particular service (URI).  A change in
   the ISTag invalidates all the other entities provided a service with
   the old ISTag, not just the entity whose response contained the
   updated ISTag.

   The syntax of an ISTag is simply:
      ISTag = "ISTag: " quoted-string

   In this document we use the quoted-string definition defined in
   section 2.2 of [4].

   For example:
      ISTag: "874900-1994-1c02798" */

static uintmax_t istag_counter;

void invalidate_istag(void){
	if(istag_counter == 0){
		istag_counter = random();
	}
	++istag_counter;
}

static int
prepare_icap_repheaders(icap_state *icap){
	#define ISTAG_MAX_OCTETS 32
	// the 1 is for the hyphen we insert before REVISION, *not* a null term
	if(strlen(Version) + 1 + strlen(REVISION) > ISTAG_MAX_OCTETS){
		bitch("Version too long to generate ISTag!\n");
		return -1;
	}
	#undef ISTAG_MAX_OCTETS
	// FIXME ensure that ISTag doesn't exceed 32 characters (RFC 3507 4.7)
	if(writeq_printf(&icap->wq,"ISTag: \"%s-%s-%ju\"" CRLF "Server: snare/%s" CRLF,
				Version,REVISION,istag_counter,Version)){
		return -1;
	}
	if(icap->respheaders){
		if(writeq_printf(&icap->wq,"%s",icap->respheaders)){
			return -1;
		}
	}
	// Now we need an ICAP "Encapsulated:" header, mandated by 3507 Err.1,
	// but this is dynamicly generated...
	return 0;
}

static int
prepare_nomod_response(int sd,icap_state *is){
	inc_nomod();
	if(prepare_icap_statusline(is,ICAPSTATUS_NO_MODIFICATION)){
		return -1;
	}
	if(prepare_icap_repheaders(is)){
		return -1;
	}
	if(prepare_icap_empty_encapheader(sd,&is->wq)){
		return -1;
	}
	if(writeq_printf(&is->wq,CRLF)){
		return -1;
	}
	icap_state_setrewritten(is);
	if(!icap_state_gotlastchunkp(is)){
		// FIXME duplicates code from transmogrify.c
		if((is->encaps.drainbody = create_icap_encapsulate(NULL)) == NULL){
			return -1;
		}
		if(drain_pollinbuf(is->pibuf,icap_drain_chunkline,icap_drain_chunkdata)){
			return -1;
		}
	}
	return 0;
}

static int
prepare_response_encap_headers(icap_state *icap,struct oqueue_key *okey){
	size_t hdroff = 0,stripe;

	// Normally, we're simply writing the chunk of request + response
	// headers en masse. We might shift up, however, if we've replaced the
	// startline; if we've added headers, they must be appended (and the
	// CRLF shifted out). Added headers always go at the end --
	// requests have headers added to request headers, responses response
	// headers, and in both cases the represent the terminating encaps.
	if(icap->encaps.http.new_startline){
		// nag("Writing %zu startline\n",strlen(icap->encaps.http.new_startline));
		if(writeq_printf(&icap->wq,"%s",icap->encaps.http.new_startline)){
			return -1;
		}
	}
	// At this point, if nothing was dynamic, we've sent nothing. Rewritten
	// startlines have been sent. Handle any encapsulated response headers,
	// combining any appended headers. Get along, lil' doggies.
	if( (stripe = hdrscratch_get_valid(&icap->encaps.http.startword)) ){
		// nag("Writing %zu stripe\n",stripe);
		if(writeq_sendfile(&icap->wq,okey,hdroff,stripe)){
			return -1;
		}
		hdroff += stripe;
	} // otherwise, interpret initial skipbuf
	while(hdroff < oqueue_usedlen(icap->encaps.hdrs)){
		const hdrscratch *hs;

		hs = hdrscratch_const_at(oqueue_const_ptrto(okey,0),hdroff);
		// nag("Skipping %u stripe\n",hdrscratch_get_skip(hs));
		hdroff += hdrscratch_get_skip(hs);
		if(hdroff >= oqueue_usedlen(icap->encaps.hdrs)){
			break;
		}
		// nag("Writing %u stripe\n",hdrscratch_get_valid(hs));
		if(hdrscratch_get_valid(hs)){
			if(writeq_sendfile(&icap->wq,okey,hdroff,hdrscratch_get_valid(hs))){
				return -1;
			}
			hdroff += hdrscratch_get_valid(hs);
		}
	}
	// hdroff should never actually exceed usedlen; sanity check --nlb
	if(hdroff != oqueue_usedlen(icap->encaps.hdrs)){
		bitch("Internal error (%zu != %zu)\n",hdroff,
				oqueue_usedlen(icap->encaps.hdrs));
		inc_stateexceptions();
		return -1;
	}
	if(writeq_printf(&icap->wq,CRLF)){
		return -1;
	}
	return 0;
}

// Response for anything besides OPTIONS (which are handled in
// prepare_options_response()) and exceptions (handled in send_icapexception())
static int
prepare_response(int sd,icap_state *icap){
	struct oqueue_key *txbody;

	nag("Prepping %s on %d\n",name_icap_method(icap->method),sd);
	/* if(icap->method == ICAP_METHOD_REQMOD){
		if(reqgzip_reqmod(icap)){
			return -1;
		}
	} */
	// We can't use icap_state_verdictp(), because we haven't yet turned on
	// the TXStarted flag (icap_state_txstartedp() == 0). FIXME
	if(!icap_state_modifiedp(icap) && !icap->encaps.body_tx_len){
		if(icap_headers_allow(&icap->headers,ICAPSTATUS_NO_MODIFICATION)){
			return prepare_nomod_response(sd,icap);
		}
	} // First, we write the ICAP status line
	if(prepare_icap_statusline(icap,ICAPSTATUS_OK)){
		return -1;
	} // Now add the static ICAP headers + Encapsulated header
	if(prepare_icap_repheaders(icap)){
		return -1;
	}
	if(prepare_icap_encapheader(sd,&icap->wq,&icap->encaps)){
		return -1;
	} // A CRLF by itself ends the ICAP headers, and begins encapsulates
	if(writeq_printf(&icap->wq,CRLF)){
		return -1;
	} // Now add any encapsulated headers
	if(prepare_response_encap_headers(icap,icap->encaps.hdrs)){
		return -1;
	}
	txbody = icap_state_txtranscoded(icap) ?
			icap->encaps.transbody : icap->encaps.body;
	if(txbody){
		size_t txlen;

		if((txlen = icap->encaps.body_tx_len) == 0){
			txlen = oqueue_usedlen(txbody);
		}
		if(txlen){
			if(enqueue_icap_chunk(icap,txbody,0,txlen,
					icap_state_rewrittenp(icap) ||
					(icap_state_gotlastchunkp(icap)
					&& !icap->encaps.body_tx_len))){
				return -1;
			}
		}
		icap->encaps.body_tx_off = txlen;
	}
	// FIXME only want to send these if we're done!
	if(icap->encaps.trailer_len){
		if(writeq_sendfile(&icap->wq,icap->encaps.body,
				oqueue_usedlen(icap->encaps.body) - icap->encaps.trailer_len,
				icap->encaps.trailer_len)){
			return -1;
		}
		if(writeq_printf(&icap->wq,CRLF)){
			return -1;
		}
	}
	return 0;
}

// RFC 3507, Section 4.10 "OPTIONS Response"
// We do not yet support previews, so don't send Preview: in the response.
static const char OPTIONS_RESPONSE_HEADERS[] =
 "Max-Connections: 1024" CRLF
 "Transfer-Complete: *" CRLF
 "Service-ID: snare" CRLF
 "Service: ICAP server (snare)" CRLF
 ;


// Pre: icap->state is one of ICAP_INTROGRESSION, ICAP_IMPACTED
static int
prepare_options_response(int sd,icap_state *icap){
	nag("Reply on %d\n",sd);
	if(prepare_icap_statusline(icap,ICAPSTATUS_OK)){
		return -1;
	}
	if(prepare_icap_repheaders(icap)){
		return -1;
	}
	if(prepare_icap_encapheader(sd,&icap->wq,&icap->encaps)){
		return -1;
	}
	if(writeq_printf(&icap->wq,"Methods: %s" CRLF "%s" CRLF,
				icap->urimethod,
				OPTIONS_RESPONSE_HEADERS)){
		return -1;
	}
	icap_state_setrewritten(icap);
	return 0;
}

int send_icapexception(struct pollfd_state *pfd,icap_status status){
	icap_state *is = get_pfd_icap(pfd);

	if(prepare_icap_statusline(is,status)){
		// Don't allow an infinite recursion
		if(status == ICAPSTATUS_INTERNAL_ERROR){
			return -1;
		}
		return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
	}
	nag("Prepping status %d on %d\n",status,pfd->pfd.fd);
	// Can't send INTERNAL_ERROR -- we already wrote the status line. We
	// no longer are assured a well-formed message, due to the absence of
	// potentially-necessary headers. We could be in a resource shortage.
	// Dump the data, close the socket.
	if(prepare_icap_repheaders(is)){
		return -1;
	}
	if(prepare_icap_empty_encapheader(pfd->pfd.fd,&is->wq)){
		return -1;
	}
	if(writeq_printf(&is->wq,CRLF)){
		return -1;
	}
	// This sd is fated for annihilation. Read no further incoming data.
	icap_state_setrxdisabled(is);
	if(disable_fd_rx(pfd)){
		return -1;
	}
	icap_state_settxstarted(is);
	return prepare_icap_tx(pfd);
}

static int
generate_icap_response_internal(icap_state *is,struct pollfd_state *pfd){
	switch(is->method){
	case ICAP_METHOD_OPTIONS: {
		if(prepare_options_response(pfd->pfd.fd,is)){
			return -1;
		}
		break;
	} case ICAP_METHOD_REQMOD: 
	  case ICAP_METHOD_RESPMOD: {
		if(prepare_response(pfd->pfd.fd,is)){
			return -1;
		}
		break;
	} case ICAP_METHOD_COUNT: default: {
		bitch("Method unsupported: %d\n",is->method);
		inc_stateexceptions();
		return -1;
	} }
	return 0;
}

// If we error out after having already placed elements into the writeq, it's
// imperative that we reset the writeq so that ICAP errors are sent cleanly.
// On entry, is->iomode must be ICAP_INTROGRESSION or ICAP_INGURGITATION. On
// exit, it will be one of ICAP_STREAMING, ICAP_INGURGITATION or ICAP_INGENUOUS.
static int
generate_icap_response(struct pollfd_state *pfd){
	icap_state *is = get_pfd_icap(pfd);

	if(generate_icap_response_internal(is,pfd)){
		reset_writeq(&is->wq);
		if(send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR)){
			return -1;
		}
		return 0;
	}
	icap_state_settxstarted(is);
	return prepare_icap_tx(pfd);
}

// By the time we leave this function, assuming we matched an icap_state, that
// icap_state can no longer be in the ICAP_INTROGRESSION state, due to
// prepare_tx() having been called. If we enter in ICAP_INTROGRESSION, thus, no
// verdict has been issued and we're not trickling. If we enter in
// ICAP_IMPACTED, a verdict might have been issued, or we might be trickling.
// If we enter in ICAP_INGURGITATION or ICAP_INGENUOUS, we can't have any real
// effect.
static inline int
icap_callback_core(struct pollfd_state *pfd,verdict v){
	icap_state *is = get_pfd_icap(pfd);

	if(v >= VERDICT_COUNT){
		bitch("Got invalid verdict %d for %d\n",v,pfd->pfd.fd);
		inc_stateexceptions();
		v = VERDICT_ERROR;
	}else if(v != VERDICT_TRICKLE){
		nag("Got verdict %s for %d status %u\n",name_verdict(v),
				pfd->pfd.fd,is ? is->status : 0);
	}
	inc_verdicts(is->method,v);
	if(is == NULL){
		nag("NULL istate, verdict cannot be applied, returning 0\n");
		inc_lateverdicts();
		return 0;
	}
	if(v == VERDICT_SKIP){
		return 0;
	}
	if(v == VERDICT_ERROR){
		return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
	}
	if(!icap_state_rewrittenp(is)){
		if(v == VERDICT_DONE){
			is->encaps.body_tx_len = 0;
			icap_state_setcbtranscoded(is,0);
		}
		if(is->status){
			// We've already begun to trickle. All we can do is
			// allow more data to flow, or abort the stream.
			struct oqueue_key *txkey = is->encaps.body;
			size_t txlen;

			if(icap_state_txtranscoded(is)){
				txkey = is->encaps.transbody;
			}
			txlen = oqueue_usedlen(txkey);
			// FIXME is body_tx_len accurate for all xcoding states?
			if(is->encaps.body_tx_len){
				txlen = is->encaps.body_tx_len;
			}
			if(txlen < is->encaps.body_tx_off){
				bitch("Can't TX through %zu from %zu\n",txlen,is->encaps.body_tx_off);
				inc_stateexceptions();
				return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
			}
			// nag("TXlen: %zu body_tx_off: %zu\n",txlen,is->encaps.body_tx_off);
			txlen -= is->encaps.body_tx_off;
			if(txlen){
				// nag("Trickling %zu through %zu (%zu)\n",is->encaps.body_tx_off,
				//	is->encaps.body_tx_off + txlen,txlen);
				if(send_icap_chunk(pfd,txkey,is->encaps.body_tx_off,txlen,
						v == VERDICT_DONE && icap_state_gotlastchunkp(is))){
					return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
				}
			}else if(v == VERDICT_DONE && icap_state_gotlastchunkp(is)){
				if(send_icap_chunk(pfd,NULL,0,0,0)){
					return send_icapexception(pfd,ICAPSTATUS_INTERNAL_ERROR);
				}
			}
			is->encaps.body_tx_off = is->encaps.body_tx_len;
			return 0;
		}
	}
	return generate_icap_response(pfd);
}

int icap_callback(struct pollfd_state *pfd,verdict v,int closeit){
	int ret;

	if( (ret = icap_callback_core(pfd,v)) ){
		if(closeit){
			ret |= close_pollqueue_fd(snarepoller,pfd->pfd.fd);
		}
	}
	return ret;
}
