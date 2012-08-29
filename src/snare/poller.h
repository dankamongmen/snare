#ifndef LIB_MODULES_POLLER_POLLER
#define LIB_MODULES_POLLER_POLLER

#include <pthread.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <snare/icap/stats.h>

struct poller;
struct ustring;
struct sockaddr;
struct pollfd_state;

struct poller *create_poller(void);
int destroy_poller(struct poller *);

void run_poller(struct poller *);

typedef int (*fdstatefxn)(struct poller *,struct pollfd_state *);
typedef void (*fdstatefreefxn)(void *);
typedef int (*fdstatestrfxn)(struct ustring *,const struct pollfd_state *);

struct pollfd_submission {
	int fd;
	void *state;
	fdstatefxn txfxn,rxfxn;
	fdstatefreefxn freefxn;
	fdstatestrfxn strfxn;
};

// FIXME internalize to poller.c
typedef struct pollfd_state {
	struct pollfd pfd;	// FIXME eliminate, no longer needed
	fdstatefxn rxfxn,txfxn,timeoutfxn;
	fdstatefreefxn freefxn;
	fdstatestrfxn strfxn;
	struct icap_state *state; // FIXME genericize via void *
	// FIXME could we combine the following two via union?
	struct sockaddr_storage peer;
	int timerfd;
	struct avgmax_stats pfd_avgmax_time; // time to handle events

	// Statistics FIXME add requests, responses
	time_t creation_time;		// time of file descriptor creation
	time_t lastuse_time;		// time of last file descriptor event
	unsigned rxcbs,txcbs;		// number of POLLIN / POLLOUT callbacks
} pollfd_state;

int block_poller(struct poller *);
int unblock_poller(struct poller *);
int enable_fd_tx(struct pollfd_state *,fdstatefxn);
int disable_fd_tx(struct pollfd_state *);
int enable_fd_rx(struct pollfd_state *,fdstatefxn);
int disable_fd_rx(struct pollfd_state *);
int add_timeout_to_pollqueue(struct poller *,int,int,fdstatefxn);
int del_timeout_from_pollqueue(struct poller *,int);
int add_fd_to_pollqueue(struct poller *,const struct pollfd_submission *,
			const struct sockaddr *,socklen_t);
int add_child_to_pollqueue(struct poller *,pid_t,fdstatefxn);
int close_pollqueue_fd(struct poller *,int);
int stringize_pfds_locked(const struct poller *,struct ustring *);
int signal_poller(struct poller *);
void inc_stateexceptions(void);
void *get_pfd_state(struct pollfd_state *);
const void *get_const_pfd_state(const struct pollfd_state *);
int set_poller_sigmask(void);
int unset_poller_sigmask(void);
void set_pollertid_hack(struct poller *); // FIXME ugh, purge
int stringize_sdbuf_sizes(struct ustring *,int);

#endif
