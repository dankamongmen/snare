#ifndef SNARE_ICAP_HEADERS
#define SNARE_ICAP_HEADERS

#ifdef __cplusplus
extern "C" {   
#endif

#include <snare/icap/status.h>
#include <libdank/objects/objustring.h>

typedef struct icap_reqhdrs {
	// RFC 3507, 4.3.1. ICAP supports certain headers with semantics
	// borrowed from HTTP/1.1, RFC 2616.
	char *cache_control,*connection,*date,*expires,*pragma,*trailer,
	     	*upgrade;

	// New headers from RFC 3507, 4.4 (first referenced in 4.3.1).
	char *encapsulated;

	// RFC 3507, 4.3.2. ICAP requests support certain headers with
	// semantics borrowed from HTTP/1.1, RFC 2616, 5.3.
	char *allow,*authorization,*from,*host,*referer,*user_agent;

	// New headers from RFC 3507, 4.5 (first referenced in 4.3.2).
	char *preview;

	// Most ICAP clients support X-Client-IP and X-Server-IP
	char *client_ipstr,*server_ipstr;

	// Newer WebWasher sends this, as either HTTP, HTTPS or FTP
	char *encapsulated_protocol;

	// BlueCoat sends this when previews are enabled
	char *scan_progress_interval;

	// WebWasher sends this, an IP numeric address
	char *proxy_ipstr;

	// WebWasher sends this, a tcp port
	char *proxy_port;

	// Newer WebWasher sends this (things like "req-cont, req-stop")
	char *chunk_extensions;
} icap_reqhdrs;

struct icap_state;

int parse_icap_header(const char *,icap_reqhdrs *);
void free_icap_reqheaders(icap_reqhdrs *);

int stringize_icap_header_stats(ustring *);
void clear_icap_header_stats(void);

int icap_headers_allow(const icap_reqhdrs *,icap_status);

#ifdef __cplusplus
}
#endif

#endif
