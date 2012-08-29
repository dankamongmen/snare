#ifndef SNARE_WRITEQ
#define SNARE_WRITEQ

struct oqueue_key;
struct pending_msg;

// FIXME opaqify
typedef struct writeq {
	struct pending_msg *pmlist,*lastpm;
} writeq;

// Associate the writequeue with the file descriptor provided.
void init_writeq(writeq *);

// Queue data to be written.
int writeq_sendfile(writeq *,struct oqueue_key *,off_t,off_t);
int writeq_printf(writeq *,const char *fmt,...)
	__attribute__ ((format (printf,2,3)));

// Send + free any enqueued messages, unless we would block or bomb out.
//  WRITEQ_RES_SUCCESS: everything was sent; enqueue data before calling again
//  WRITEQ_RES_NBLOCK: call again once poll() returns POLLOUT for the fd
//  WRITEQ_RES_SYSERR: system error; don't call again
typedef enum {
	WRITEQ_RES_SUCCESS,
	WRITEQ_RES_NBLOCK,
	WRITEQ_RES_SYSERR
} writeq_res;

writeq_res send_writeq_data(writeq *,int);

static inline int
writeq_emptyp(const writeq *wq){
	return !wq->pmlist;
}

// Clean up the writequeue and all pending messages.
void reset_writeq(writeq *);

#endif
