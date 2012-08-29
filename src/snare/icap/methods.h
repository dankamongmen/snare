#ifndef SNARE_ICAP_METHODS
#define SNARE_ICAP_METHODS

#ifdef __cplusplus
extern "C" {   
#endif

typedef enum {
	ICAP_METHOD_OPTIONS,
	ICAP_METHOD_REQMOD,
	ICAP_METHOD_RESPMOD,
	ICAP_METHOD_COUNT
} icap_method;

icap_method parse_method(char **);
const char *name_icap_method(icap_method);

#ifdef __cplusplus
}
#endif

#endif
