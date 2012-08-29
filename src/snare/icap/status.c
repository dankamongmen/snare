#include <stdio.h>
#include <snare/icap/status.h>

static struct {
	const char *phrase;
	icap_status code;
} statcodetable[] = {
	#define DECLARESTATUS(statphrase,statcode) \
	{ .phrase = statphrase, .code = statcode, }
	DECLARESTATUS("Continue after ICAP Preview",ICAPSTATUS_CONTINUE_AFTER_PREVIEW),
	DECLARESTATUS("Switching Protocols",ICAPSTATUS_SWITCHING_PROTOCOLS),
	DECLARESTATUS("OK",ICAPSTATUS_OK),
	DECLARESTATUS("Created",ICAPSTATUS_CREATED),
	DECLARESTATUS("Accepted",ICAPSTATUS_ACCEPTED),
	DECLARESTATUS("Non-Authoritative Information",ICAPSTATUS_NONAUTHORITATIVE),
	DECLARESTATUS("No modifications needed",ICAPSTATUS_NO_MODIFICATION),
	DECLARESTATUS("Reset Content",ICAPSTATUS_RESET_CONTENT),
	DECLARESTATUS("Partial Content",ICAPSTATUS_PARTIAL_CONTENT),
	DECLARESTATUS("Bad request",ICAPSTATUS_BAD_REQUEST),
	DECLARESTATUS("ICAP Service not found",ICAPSTATUS_SERVICE_NOT_FOUND),
	DECLARESTATUS("Method not allowed for service",ICAPSTATUS_METHOD_BAD_SERVICE),
	DECLARESTATUS("Request timeout",ICAPSTATUS_REQUEST_TIMEOUT),
	DECLARESTATUS("Bad composition",ICAPSTATUS_BAD_COMPOSITION),
	DECLARESTATUS("Server error",ICAPSTATUS_INTERNAL_ERROR),
	DECLARESTATUS("Method not implemented",ICAPSTATUS_METHOD_NOT_IMPLEMENTED),
	DECLARESTATUS("Bad Gateway",ICAPSTATUS_BAD_GATEWAY),
	DECLARESTATUS("Service overloaded",ICAPSTATUS_SERVICE_OVERLOADED),
	DECLARESTATUS("ICAP version not supported by server",ICAPSTATUS_VERSION_NOT_SUPPORTED),
	DECLARESTATUS(NULL,ICAPSTATUS_MAX)
	#undef DECLARESTATUS
};

const char *phrase_of_statcode(icap_status istat){
	typeof(*statcodetable) *cur;

	for(cur = statcodetable ; cur->phrase ; ++cur){
		if(cur->code == istat){
			break;
		}
	}
	return cur->phrase;
}
