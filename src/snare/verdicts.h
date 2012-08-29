#ifndef SNARE_VERDICTS
#define SNARE_VERDICTS

// Order is important here; see stats.c!
typedef enum {
	VERDICT_ERROR,
	VERDICT_DONE,
	VERDICT_TRICKLE,
	VERDICT_SKIP,
	VERDICT_COUNT
} verdict;

const char *name_verdict(verdict);

#endif
