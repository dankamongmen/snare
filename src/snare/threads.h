#ifndef SNARE_THREADS
#define SNARE_THREADS

struct poller;

extern struct poller * restrict snarepoller;

int launch_poller_thread(struct poller *);
int reap_poller_thread(struct poller *);

int block_all_pollers(void);
int unblock_all_pollers(void);

#endif
