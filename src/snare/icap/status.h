#ifndef SNARE_ICAP_STATUS
#define SNARE_ICAP_STATUS

#ifdef __cplusplus
extern "C" {   
#endif

// RFC 3507, 4.3.3. ICAP responses MUST start with an ICAP status line, similar
// in form to that used by HTTP, including the ICAP version and a status code.
// For example: ICAP/1.0 200 OK
// Semantics of ICAP status codes in ICAP match the status codes defined by
// HTTP (Section 6.1.1 and 10 of [4]), except where otherwise indicated in this
// document; n.b. 100 (Section 4.5) and 204 (Section 4.6)... As in HTTP, the
// 4xx class of error codes indicate client errors, and the 5xx class indicate
// server errors.
typedef enum {
	// RFC 3507, 4.5 (first referenced in 4.3.3). Overloads RFC 2616
	// 10.1.1 (6.1.1)'s more basic "Continue"
	ICAPSTATUS_CONTINUE_AFTER_PREVIEW = 100,
	ICAPSTATUS_SWITCHING_PROTOCOLS = 101, // RFC 2616, 10.1.2 (6.1.1)
	ICAPSTATUS_OK = 200, // RFC 2616, 10.2.1 (6.1.1)
	ICAPSTATUS_CREATED = 201, // RFC 2616, 10.2.2 (6.1.1)
	ICAPSTATUS_ACCEPTED = 202, // RFC 2616, 10.2.3 (6.1.1)
	ICAPSTATUS_NONAUTHORITATIVE = 203, // RFC 2616, 10.2.4 (6.1.1)
	// RFC 3507, 4.6 (first referenced in 4.3.3). Overloads RFC 2616
	// 10.2.5 (6.1.1)'s "No content"
	ICAPSTATUS_NO_MODIFICATION = 204,
	ICAPSTATUS_RESET_CONTENT = 205, // RFC 2616, 10.2.6 (6.1.1)
	ICAPSTATUS_PARTIAL_CONTENT = 206, // RFC 2616, 10.2.7 (6.1.1)
	// Unless otherwise noted, the following all come from RFC 3507, 4.3.3.
	ICAPSTATUS_BAD_REQUEST = 400,
	ICAPSTATUS_SERVICE_NOT_FOUND = 404,
	ICAPSTATUS_METHOD_BAD_SERVICE = 405,
	ICAPSTATUS_REQUEST_TIMEOUT = 408,
	// ICAP Errata #5 "Rejecting Encapsulated Sections"
	ICAPSTATUS_BAD_COMPOSITION = 418,
	ICAPSTATUS_INTERNAL_ERROR = 500, // RFC 2616, 10.5.1 (6.1.1)
	ICAPSTATUS_METHOD_NOT_IMPLEMENTED = 501,
	ICAPSTATUS_BAD_GATEWAY = 502,
	ICAPSTATUS_SERVICE_OVERLOADED = 503,
	ICAPSTATUS_VERSION_NOT_SUPPORTED = 505,
	ICAPSTATUS_MAX
} icap_status;

const char *phrase_of_statcode(icap_status);

#ifdef __cplusplus
}
#endif

#endif
