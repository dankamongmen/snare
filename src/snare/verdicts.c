#include <string.h>
#include <snare/verdicts.h>
#include <libdank/utils/parse.h>
#include <libdank/objects/logctx.h>

static const struct {
	const char *verdictname;
	verdict v;
} verdicts[] = {
	#define DECLAREVERDICT(verdict)		\
	{	.verdictname = #verdict,	\
		.v = VERDICT_##verdict,		\
	}
	DECLAREVERDICT(ERROR),
	DECLAREVERDICT(DONE),
	DECLAREVERDICT(SKIP),
	DECLAREVERDICT(TRICKLE),
	DECLAREVERDICT(COUNT),
	#undef DECLAREVERDICT
	{	.verdictname = NULL,
		.v = VERDICT_COUNT + 1,
	}
};

const char *name_verdict(verdict v){
	const typeof(*verdicts) *cur;

	for(cur = verdicts ; cur->verdictname ; ++cur){
		if(cur->v == v){
			return cur->verdictname;
		}
	}
	bitch("Unknown verdict: %d\n",v);
	return cur->verdictname;
}
