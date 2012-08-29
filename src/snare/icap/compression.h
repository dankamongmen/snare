#ifndef SNARE_ICAP_COMPRESSION
#define SNARE_ICAP_COMPRESSION

#ifdef __cplusplus
extern "C" {
#endif

struct icap_state;
struct zlib_interface;

#include <zlib.h>

int zlib_init(void);
int zlib_destroy(void);

// FIXME hide all of these
const char *zliberror(int);
int zlib_deflate_free(z_stream *);
int zlib_deflate_init(z_stream *);
// end FIXME

int reqgzip_reqmod(struct icap_state *);
int offergzip_response(struct icap_state *);

int freegzip_state(struct icap_state *);
void orphangzip_state(struct icap_state *);
int zlib_transform(struct icap_state *,size_t,size_t,size_t *);

// See RFC 2616 Section 3.5 for information on the Content-Encoding header.
// For GZip vs Deflate info, see http://www.zlib.net/zlib_faq.html#faq18 and 19
// Good overall info: http://www.http-compression.com/
#define HTTP_CONTENT_ENCODING_GZIP 	0x01	// RFC 1952 (gzip) (LZ77 + CRC32)
#define HTTP_CONTENT_ENCODING_DEFLATE	0x02	// RFC 1950 (zlib), 1951 (deflate)
#define HTTP_CONTENT_ENCODING_COMPRESS	0x04	// UNIX compress (LZW)
#define HTTP_CONTENT_ENCODING_BZIP2	0x08

unsigned encoding_compression_values(const char *);

#ifdef __cplusplus
}
#endif

#endif
