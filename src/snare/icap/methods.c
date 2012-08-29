#include <string.h>
#include <snare/icap/methods.h>
#include <libdank/utils/parse.h>
#include <libdank/utils/string.h>
#include <libdank/objects/logctx.h>

static const struct {
	const char *methodname;
	icap_method icapmethod;
} icap_methods[] = {
	#define DECLAREMETHOD(method)			\
	{	.methodname = #method,			\
		.icapmethod = ICAP_METHOD_##method,	\
	}
	DECLAREMETHOD(REQMOD),
	DECLAREMETHOD(RESPMOD),
	DECLAREMETHOD(OPTIONS),
	#undef DECLAREMETHOD
	{	.methodname = NULL,
		.icapmethod = ICAP_METHOD_COUNT,
	}
};

icap_method parse_method(char **buf){
	const typeof(*icap_methods) *cur;

	parse_whitespaces(buf);
	for(cur = icap_methods ; cur->methodname ; ++cur){
		if(!strncasecmp(*buf,cur->methodname,strlen(cur->methodname))){
			char *uri = *buf + strlen(cur->methodname);

			if(isspace(*uri)){
				*buf = uri;
				return cur->icapmethod;
			}
		}
	}
	bitch("Unknown ICAP method\n");
	return cur->icapmethod;
}

const char *name_icap_method(icap_method imeth){
	const typeof(*icap_methods) *cur;

	for(cur = icap_methods ; cur->methodname ; ++cur){
		if(cur->icapmethod == imeth){
			break;
		}
	}
	if(cur->methodname){
		return cur->methodname;
	}
	bitch("Unknown ICAP method: %d\n",imeth);
	return "UNINITIALIZED";
}
