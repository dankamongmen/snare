#include <zlib.h>
#include <ctype.h>
#include <snare/oqueue.h>
#include <snare/icap/stats.h>
#include <snare/icap/request.h>
#include <snare/icap/compression.h>
#include <libdank/utils/memlimit.h>
#include <snare/icap/transmogrify.h>

typedef struct zlib_interface {
	int (*transfxn)(struct icap_state *,size_t,size_t,size_t *);
	int (*initfxn)(z_stream *);
	int (*freefxn)(z_stream *);
	void (*orphanfxn)(z_stream *);
} zlib_interface;

const char *zliberror(int err){
	switch(err){
		case Z_OK: return "Z_OK/Success";
		case Z_STREAM_END: return "Z_STREAM_END/Stream completed";
		case Z_NEED_DICT: return "Z_NEED_DICT/Need dictionary";
		case Z_ERRNO: return "Z_ERRNO/System fd error";
		case Z_STREAM_ERROR: return "Z_STREAM_ERROR/Invalid compression level";
		case Z_DATA_ERROR: return "Z_DATA_ERROR/Invalid argument";
		case Z_MEM_ERROR: return "Z_MEM_ERROR/Insufficient memory";
		case Z_BUF_ERROR: return "Z_BUF_ERROR/No progress was possible";
		case Z_VERSION_ERROR: return "Z_VERSION_ERROR/Incompatible version";
		default: break;
	}
	return "Unknown error";
}

static void *
zMallocWrapper(void *opaque,unsigned n,unsigned s){
	if(opaque){
		bitch("Didn't expect valid pointer %p\n",opaque);
		return NULL;
	}
	return Malloc("zlib",n * s);
}

static void
zFreeWrapper(void *opaque,void *addr){
	if(opaque){
		bitch("Didn't expect valid pointer %p\n",opaque);
	}
	Free(addr);
}

static int
icap_body_deflate(icap_state *is,size_t offset,size_t len,size_t *s){
	oqueue_key *norm;

	// When chunk->len == 0, deflate_icap_encapsulate() will set Z_FINISH,
	// necessary for correct operation.
	norm = is->encaps.body;
	is->encaps.zstream.next_in = (Bytef *)oqueue_ptrto(norm,offset);
	is->encaps.zstream.avail_in = len;
	if(deflate_icap_encapsulate(is->encaps.transbody,&is->encaps.zstream,s)){
		inc_deflateerr();
		return -1;
	}
	inc_chunks_gzipped();
	inc_gzip_back_octets((intmax_t)len - (intmax_t)*s);
	return 0;
}

// Takes as input a z_stream, previously initialized with inflateInit(),
// which now needs be reconstructed as an RFC 1951 "raw" stream processor.
static int
zlib_broken1951inflate_init(z_stream *strm){
	int ret;

	if((ret = inflateEnd(strm)) != Z_OK){
		bitch("Couldn't prep inflate for reinit (%s?)\n",zliberror(ret));
		return -1;
	}
	memset(strm,0,sizeof(*strm));
	strm->zalloc = zMallocWrapper;
	strm->zfree = zFreeWrapper;
	strm->opaque = NULL;
	if((ret = inflateInit2(strm,-MAX_WBITS)) != Z_OK){
		bitch("Couldn't reinitialize inflate (%s?)\n",zliberror(ret));
		return -1;
	}
	return 0;
}

/* from zlib.h (debian zlib1g-dev 1:1.2.3.3.dfsg-12)

    inflate decompresses as much data as possible, and stops when the input
  buffer becomes empty or the output buffer becomes full. It may introduce
  some output latency (reading input without producing any output) except when
  forced to flush.

  The detailed semantics are as follows. inflate performs one or both of the
  following actions:

  - Decompress more input starting at next_in and update next_in and avail_in
    accordingly. If not all input can be processed (because there is not
    enough room in the output buffer), next_in is updated and processing
    will resume at this point for the next call of inflate().

  - Provide more output starting at next_out and update next_out and avail_out
    accordingly.  inflate() provides as much output as possible, until there
    is no more input data or no more space in the output buffer (see below
    about the flush parameter).

  Before the call of inflate(), the application should ensure that at least
  one of the actions is possible, by providing more input and/or consuming
  more output, and updating the next_* and avail_* values accordingly.
  The application can consume the uncompressed output when it wants, for
  example when the output buffer is full (avail_out == 0), or after each
  call of inflate(). If inflate returns Z_OK and with zero avail_out, it
  must be called again after making room in the output buffer because there
  might be more output pending.

    The flush parameter of inflate() can be Z_NO_FLUSH, Z_SYNC_FLUSH,
  Z_FINISH, or Z_BLOCK. Z_SYNC_FLUSH requests that inflate() flush as much
  output as possible to the output buffer. Z_BLOCK requests that inflate() stop
  if and when it gets to the next deflate block boundary. When decoding the
  zlib or gzip format, this will cause inflate() to return immediately after
  the header and before the first block. When doing a raw inflate, inflate()
  will go ahead and process the first block, and will return when it gets to
  the end of that block, or when it runs out of data.

    The Z_BLOCK option assists in appending to or combining deflate streams.
  Also to assist in this, on return inflate() will set strm->data_type to the
  number of unused bits in the last byte taken from strm->next_in, plus 64
  if inflate() is currently decoding the last block in the deflate stream,
  plus 128 if inflate() returned immediately after decoding an end-of-block
  code or decoding the complete header up to just before the first byte of the
  deflate stream. The end-of-block will not be indicated until all of the
  uncompressed data from that block has been written to strm->next_out.  The
  number of unused bits may in general be greater than seven, except when
  bit 7 of data_type is set, in which case the number of unused bits will be
  less than eight.

    inflate() should normally be called until it returns Z_STREAM_END or an
  error. However if all decompression is to be performed in a single step
  (a single call of inflate), the parameter flush should be set to
  Z_FINISH. In this case all pending input is processed and all pending
  output is flushed; avail_out must be large enough to hold all the
  uncompressed data. (The size of the uncompressed data may have been saved
  by the compressor for this purpose.) The next operation on this stream must
  be inflateEnd to deallocate the decompression state. The use of Z_FINISH
  is never required, but can be used to inform inflate that a faster approach
  may be used for the single inflate() call.

     In this implementation, inflate() always flushes as much output as
  possible to the output buffer, and always uses the faster approach on the
  first call. So the only effect of the flush parameter in this implementation
  is on the return value of inflate(), as noted below, or when it returns early
  because Z_BLOCK is used.

     If a preset dictionary is needed after this call (see inflateSetDictionary
  below), inflate sets strm->adler to the adler32 checksum of the dictionary
  chosen by the compressor and returns Z_NEED_DICT; otherwise it sets
  strm->adler to the adler32 checksum of all output produced so far (that is,
  total_out bytes) and returns Z_OK, Z_STREAM_END or an error code as described
  below. At the end of the stream, inflate() checks that its computed adler32
  checksum is equal to that saved by the compressor and returns Z_STREAM_END
  only if the checksum is correct.

    inflate() will decompress and check either zlib-wrapped or gzip-wrapped
  deflate data.  The header type is detected automatically.  Any information
  contained in the gzip header is not retained, so applications that need that
  information should instead use raw inflate, see inflateInit2() below, or
  inflateBack() and perform their own processing of the gzip header and
  trailer.

    inflate() returns Z_OK if some progress has been made (more input processed
  or more output produced), Z_STREAM_END if the end of the compressed data has
  been reached and all uncompressed output has been produced, Z_NEED_DICT if a
  preset dictionary is needed at this point, Z_DATA_ERROR if the input data was
  corrupted (input stream not conforming to the zlib format or incorrect check
  value), Z_STREAM_ERROR if the stream structure was inconsistent (for example
  if next_in or next_out was NULL), Z_MEM_ERROR if there was not enough memory,
  Z_BUF_ERROR if no progress is possible or if there was not enough room in the
  output buffer when Z_FINISH is used. Note that Z_BUF_ERROR is not fatal, and
  inflate() can be called again with more input and more output space to
  continue decompressing. If Z_DATA_ERROR is returned, the application may then
  call inflateSync() to look for a good compression block if a partial recovery
  of the data is desired. */
static int
icap_body_inflate(icap_state *is,size_t offset,size_t len,size_t *s){
	oqueue_key *norm;

	if(len == 0){
		*s = 0;
		return 0;
	}
	norm = is->encaps.body;
	is->encaps.zstream.next_in = (Bytef *)oqueue_ptrto(norm,offset);
	// nag("inflating %zu at %zu\n",len,offset);
	if(inflate_icap_encapsulate(is->encaps.transbody,&is->encaps.zstream,len,s)){
		// Hack to support broken HTTP servers/proxies/accelerators
		// which have misread RFC 2616 such that they use RFC 1951
		// (raw) deflate instead of an RFC 1950 (zlib) deflate. This
		// isn't perfect and I'd like a better solution...FIXME
		if(!offset){
			if(!zlib_broken1951inflate_init(&is->encaps.zstream)){
				is->encaps.zstream.next_in = (Bytef *)oqueue_ptrto(norm,offset);
				if(inflate_icap_encapsulate(is->encaps.transbody,&is->encaps.zstream,len,s) == 0){
					inc_chunks_gunzipped();
					return 0;
				}
			}
		}
		if(errno != ENOMEM){
			nag("Disabling session transcoding\n");
			inc_inflateerr();
			icap_state_setcbtranscoded(is,0);
			*s = len; // send any data not yet written as transcode
			return 0;
		}
		return -1;
	}
	inc_chunks_gunzipped();
	inc_gzip_front_octets((intmax_t)*s - (intmax_t)len);
	return 0;
}

int zlib_transform(icap_state *is,size_t offset,size_t len,size_t *s){
	return is->encaps.transapi->transfxn(is,offset,len,s);
}

int zlib_init(void){
	if(strcmp(zlibVersion(),ZLIB_VERSION)){
		bitch("Zlib version mismatch: %s != %s\n",zlibVersion(),ZLIB_VERSION);
		return -1;
	}
	nag("Initialized zlib, version %s\n",ZLIB_VERSION);
	return 0;
}

/* from zlib.h (debian zlib1g-dev 1:1.2.3.3.dfsg-12)

     Initializes the internal stream state for compression. The fields
   zalloc, zfree and opaque must be initialized before by the caller.
   If zalloc and zfree are set to Z_NULL, deflateInit updates them to
   use default allocation functions.

     The compression level must be Z_DEFAULT_COMPRESSION, or between 0 and 9:
   1 gives best speed, 9 gives best compression, 0 gives no compression at
   all (the input data is simply copied a block at a time).
   Z_DEFAULT_COMPRESSION requests a default compromise between speed and
   compression (currently equivalent to level 6).

     deflateInit returns Z_OK if success, Z_MEM_ERROR if there was not
   enough memory, Z_STREAM_ERROR if level is not a valid compression level,
   Z_VERSION_ERROR if the zlib library version (zlib_version) is incompatible
   with the version assumed by the caller (ZLIB_VERSION).
   msg is set to null if there is no error message.  deflateInit does not
   perform any compression: this will be done by deflate(). */
int zlib_deflate_init(z_stream *strm){
	int ret;

	memset(strm,0,sizeof(*strm));
	strm->zalloc = zMallocWrapper;
	strm->zfree = zFreeWrapper;
	strm->opaque = Z_NULL;
	if((ret = deflateInit(strm,Z_DEFAULT_COMPRESSION)) != Z_OK){
		bitch("Couldn't initialize deflate (%s?)\n",zliberror(ret));
		return -1;
	}
	return 0;
}

static int
zlib_gzip_init(z_stream *strm){
	int ret;

	memset(strm,0,sizeof(*strm));
	strm->zalloc = zMallocWrapper;
	strm->zfree = zFreeWrapper;
	strm->opaque = Z_NULL;
	if((ret = deflateInit2(strm,Z_DEFAULT_COMPRESSION,Z_DEFLATED,31,8,Z_DEFAULT_STRATEGY)) != Z_OK){
		bitch("Couldn't initialize gzip (%s?)\n",zliberror(ret));
		return -1;
	}
	return 0;
}

/* from zlib.h (debian zlib1g-dev 1:1.2.3.3.dfsg-12)

     All dynamically allocated data structures for this stream are freed.
   This function discards any unprocessed input and does not flush any
   pending output.

     deflateEnd returns Z_OK if success, Z_STREAM_ERROR if the
   stream state was inconsistent, Z_DATA_ERROR if the stream was freed
   prematurely (some input or output was discarded). In the error case,
   msg may be set but then points to a static string (which must not be
   deallocated). */
int zlib_deflate_free(z_stream *strm){
	int ret;

	if((ret = deflateEnd(strm)) != Z_OK){
		bitch("Couldn't free deflate (%s?)\n",zliberror(ret));
		return -1;
	}
	return 0;
}

static void
zlib_deflate_orphan(z_stream *strm){
	int ret;

	if((ret = deflateEnd(strm)) != Z_OK){
		if(ret != Z_DATA_ERROR){ // Z_DATA_ERROR is acceptable
			nag("Couldn't free deflate (%s?)\n",zliberror(ret));
		}
	}
}

static int
zlib_inflate_init(z_stream *strm){
	int ret;

	memset(strm,0,sizeof(*strm));
	strm->zalloc = zMallocWrapper;
	strm->zfree = zFreeWrapper;
	strm->opaque = NULL;
	if((ret = inflateInit2(strm,-MAX_WBITS)) != Z_OK){
		bitch("Couldn't initialize inflate (%s?)\n",zliberror(ret));
		return -1;
	}
	return 0;
}

static int
zlib_gunzip_init(z_stream *strm){
	int ret;

	memset(strm,0,sizeof(*strm));
	strm->zalloc = zMallocWrapper;
	strm->zfree = zFreeWrapper;
	strm->opaque = NULL;
	// FIXME adapted from curl's lib/transfer-encoding.c...from whence 32?
	if((ret = inflateInit2(strm,MAX_WBITS + 32)) != Z_OK){
		bitch("Couldn't initialize gunzip (%s?)\n",zliberror(ret));
		return -1;
	}
	return 0;
}

/* from zlib.h (debian zlib1g-dev 1:1.2.3.3.dfsg-12)

     All dynamically allocated data structures for this stream are freed.
   This function discards any unprocessed input and does not flush any
   pending output.

     inflateEnd returns Z_OK if success, Z_STREAM_ERROR if the stream state
   was inconsistent. In the error case, msg may be set but then points to a
   static string (which must not be deallocated). */
static int
zlib_inflate_free(z_stream *strm){
	int ret;

	if((ret = inflateEnd(strm)) != Z_OK){
		bitch("Couldn't free inflate (%s?)\n",zliberror(ret));
		return -1;
	}
	return 0;
}

static void
zlib_inflate_orphan(z_stream *strm){
	int ret;

	if((ret = inflateEnd(strm)) != Z_OK){
		nag("Couldn't free inflate (%s?)\n",zliberror(ret));
	}
}

int zlib_destroy(void){
	return 0;
}

unsigned encoding_compression_values(const char *encoding){
	unsigned ret = 0;

	// nag("Extracting from %s\n",encoding);
	while(*encoding){ // Exit only upon hitting a NUL byte
		const char *tokstart,*tokend;
		static const struct {
			const char *id;
			size_t slen;
			unsigned bit;
		} encodemap[] = { // FIXME these constants are fucking weak
			{ .id = "deflate",	.slen = 7,
				.bit = HTTP_CONTENT_ENCODING_DEFLATE, },
			{ .id = "gzip",		.slen = 4,
				.bit = HTTP_CONTENT_ENCODING_GZIP, },
			{ .id = "compress",	.slen = 8,
				.bit = HTTP_CONTENT_ENCODING_COMPRESS, },
			{ .id = "bzip2",	.slen = 5,
				.bit = HTTP_CONTENT_ENCODING_BZIP2, },
			{ .id = "x-gzip",	.slen = 6,
				.bit = HTTP_CONTENT_ENCODING_GZIP, },
			{ .id = "x-compress",	.slen = 10,
				.bit = HTTP_CONTENT_ENCODING_COMPRESS, },
			{ .id = "identity",	.slen = 8,	.bit = 0, },
			{ .id = NULL,		.slen = 0,	.bit = 0, }
		},*cur;

		while(isspace(*encoding)){
			++encoding;
		}
		tokstart = encoding;
		while(*encoding && *encoding != ','){
			++encoding;
		}
		tokend = encoding;
		for(cur = encodemap ; cur->id ; ++cur){
			if((size_t)(tokend - tokstart) == cur->slen){
				if(strncasecmp(tokstart,cur->id,cur->slen) == 0){
					// check to see if already set? ...
					ret |= cur->bit;
					break;
				}
			}
		}
		if(*encoding == ','){
			++encoding;
		}
	}
	return ret;
}

static const zlib_interface compress_api = {
	.transfxn = icap_body_deflate,
	.initfxn = zlib_deflate_init,
	.freefxn = zlib_deflate_free,
	.orphanfxn = zlib_deflate_orphan,
};

static const zlib_interface gzip_api = {
	.transfxn = icap_body_deflate,
	.initfxn = zlib_gzip_init,
	.freefxn = zlib_deflate_free,
	.orphanfxn = zlib_deflate_orphan,
};

static const zlib_interface inflate_api = {
	.transfxn = icap_body_inflate,
	.initfxn = zlib_inflate_init,
	.freefxn = zlib_inflate_free,
	.orphanfxn = zlib_inflate_orphan,
};

static const zlib_interface gunzip_api = {
	.transfxn = icap_body_inflate,
	.initfxn = zlib_gunzip_init,
	.freefxn = zlib_inflate_free,
	.orphanfxn = zlib_inflate_orphan,
};

// RFC2616, Section 14.11 "Content-Encoding"
//
// The Content-Encoding entity-header field is used as a modifier to the
// media-type. When present, its value indicates what additional content
// codings have been applied to the entity-body, and thus what decoding
// mechanisms must be applied in order to obtain the media-type referenced by
// the Content-Type header field. Content-Encoding is primarily used to allow a
// document to be compressed without losing the identity of its underlying
// media type.
//
//  Content-Encoding  = "Content-Encoding" ":" 1#content-coding
//
// Content codings are defined in section 3.5. An example of its use is
//
//  Content-Encoding: gzip
//
// The content-coding is a characteristic of the entity identified by the
// Request-URI. Typically, the entity-body is stored with this encoding and is
// only decoded before rendering or analogous usage. However, a non-transparent
// proxy MAY modify the content-coding if the new coding is known to be
// acceptable to the recipient, unless the "no-transform" cache-control
// directive is present in the message.
//
// If the content-coding of an entity is not "identity", then the response MUST
// include a Content-Encoding entity-header (section 14.11) that lists the
// non-identity content-coding(s) used.
//
// If the content-coding of an entity in a request message is not acceptable to
// the origin server, the server SHOULD respond with a status code of 415
// (Unsupported Media Type).
//
// If multiple encodings have been applied to an entity, the content codings
// MUST be listed in the order in which they were applied. Additional
// information about the encoding parameters MAY be provided by other
// entity-header fields not defined by this specification.
//
// FIXME rewrite as function accepting int cli! this is gross
#define REWRITE_REPLY(method,oldenc,is,apiptr) do { \
	ustring newenc = USTRING_INITIALIZER; \
	\
	if(oldenc){ \
		nag("Browsers can't handle multiple encodings; bailing\n"); \
		return 0; \
		/* if(printUString(&newenc,"%s : %s",#method,oldenc) < 0){ \
			return -1; \
		} FIXME http://bugs.research.sys/bugzilla/show_bug.cgi?id=897 */ \
	}else{ \
		if(printUString(&newenc,"%s",#method) < 0){ \
			return -1; \
		} \
	} \
	inc_gzip_postload(); \
	icap_state_settxtranscoded(is,1); \
	(is)->encaps.transapi = (apiptr); \
	if(rewrite_icap_http_header(is,"Content-Encoding:",newenc.string)){ \
		reset_ustring(&newenc); \
		return -1; \
	} \
	reset_ustring(&newenc); \
	if(rewrite_icap_http_header(is,"Content-Length:",NULL)){ \
		return -1; \
	} \
}while(0)

int freegzip_state(icap_state *is){
	int ret = 0;

	if(is->encaps.transapi){
		ret = is->encaps.transapi->freefxn(&is->encaps.zstream);
		is->encaps.transapi = NULL;
	}
	return ret;
}

void orphangzip_state(icap_state *is){
	if(is->encaps.transapi){
		is->encaps.transapi->orphanfxn(&is->encaps.zstream);
		is->encaps.transapi = NULL;
	}
}

int offergzip_response(icap_state *is){
	struct icap_http_headers *hdrs = &is->encaps.http;
	const char *oldenc,*acceptenc;
	unsigned serv = 0,cli = 0;

	// Don't apply or advertise any transcoding on null encapsulates
	if(is->encaps.bodytype == ICAP_ENCAPSULATE_BODY_NULL){
		return 0;
	}
	if( (oldenc = httphdr_lookup_contentencoding(hdrs)) ){
		serv = encoding_compression_values(oldenc);
	}
	if( (acceptenc = httphdr_lookup_acceptencoding(hdrs)) ){
		cli = encoding_compression_values(acceptenc);
	}
	if((cli | serv) != cli){
		nag("Got unrequested encodings in reply (%u / %u)\n",cli,serv);
		// should we allow this? might be some kind of exploit...
		// actually, there is a real server bug in the wild here, where
		// tarballs (.tgz's) are returned as Content-Type: x-tar and
		// Content-Encoding: x-gzip (!) Act as the browser does....
		inc_gzip_server();
	}else if(serv){
		icap_state_setcbtranscoded(is,1);
		if(serv & HTTP_CONTENT_ENCODING_DEFLATE){
			is->encaps.transapi = &inflate_api;
		}else{
			is->encaps.transapi = &gunzip_api;
		} // FIXME else what?
		if(httphdr_lookup_x_snare_varied(hdrs)){
			icap_state_settxtranscoded(is,1);
			inc_gzip_preload();
			nag("Inserted compreq succeeded (%u / %u)\n",cli,serv);
			// FIXME only remove the compression; leave any others!
			if(rewrite_icap_http_header(is,"Content-Encoding:",NULL)){
				return -1;
			}
			if(rewrite_icap_http_header(is,"Content-Length:",NULL)){
				return -1;
			}
		}else{
			nag("Compression used natively (%u / %u)\n",cli,serv);
			inc_gzip_native();
		}
	// Reaching this point in the if() block means the server did not encode.
	// There's a chance that the client wanted encoding, though, which we can
	// satisfy. If we inserted 
	}else if(!httphdr_lookup_x_snare_varied(hdrs)){
		if(cli & HTTP_CONTENT_ENCODING_GZIP){
			REWRITE_REPLY(gzip,oldenc,is,&gzip_api);
		}else if(cli & HTTP_CONTENT_ENCODING_DEFLATE){
			REWRITE_REPLY(deflate,oldenc,is,&compress_api);
		}else{
			inc_gzip_unused();
		}
	}else{
		nag("Compression-ignorant client/server (%u / %u)\n",cli,serv);
		inc_gzip_unused();
	}
	if(is->encaps.transapi){
		if(is->encaps.transapi->initfxn(&is->encaps.zstream)){
			return -1;
		}
		if((is->encaps.transbody = create_icap_encapsulate(NULL)) == NULL){
			return -1;
		}
	}
	return 0;
}

int reqgzip_reqmod(icap_state *is){
	const char *oldenc;
	unsigned cli;

	if( (oldenc = httphdr_lookup_acceptencoding(&is->encaps.http)) ){
		cli = encoding_compression_values(oldenc);
	}else{
		cli = 0;
	}
	if(!(cli & (HTTP_CONTENT_ENCODING_DEFLATE | HTTP_CONTENT_ENCODING_GZIP))){
		ustring newenc = USTRING_INITIALIZER;
#define NEWSTR "deflate, gzip"
		
		if(oldenc){
			if(printUString(&newenc,"%s, %s",NEWSTR,oldenc) < 0){
				return -1;
			}
		}else{
			if(printUString(&newenc,"%s",NEWSTR) < 0){
				return -1;
			}
		}
		if(rewrite_icap_http_header(is,"Accept-Encoding:",newenc.string)){
			reset_ustring(&newenc);
			return -1;
		}
		if(rewrite_icap_http_header(is,"X-Snare-Varied:",newenc.string)){
			reset_ustring(&newenc);
			return -1;
		}
		reset_ustring(&newenc);
#undef NEWSTR
		inc_gzip_inserted();
	}
	return 0;
}
