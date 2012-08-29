#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <snare/poller.h>
#include <snare/server.h>
#include <snare/threads.h>
#include <snare/icap/stats.h>
#include <libdank/utils/fds.h>
#include <libdank/utils/time.h>
#include <libdank/utils/netio.h>
#include <libdank/utils/maxfds.h>
#include <libdank/ersatz/compat.h>
#include <libdank/utils/syswrap.h>
#include <libdank/utils/threads.h>
#include <libdank/utils/memlimit.h>
// FIXME base this off a more core define
#ifdef LIB_COMPAT_FREEBSD
#include <sys/event.h>
#define POLLER_KQUEUE
#else
#ifdef LIB_COMPAT_LINUX
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#define POLLER_EPOLL
#endif
#endif

typedef struct poller {
#ifdef POLLER_KQUEUE
	int_fast32_t kq;
	uint_fast32_t ksize,csize,kchanges;
	struct kevent *kv,*cv;
#else
#ifdef POLLER_EPOLL
	int_fast32_t epfd;
	uint_fast32_t esize;
	struct epoll_event *ev;
#endif
#endif
	pollfd_state *fdstates;
	unsigned pfds_active,max_pfds_active;
	int pfds_available;
	avgmax_stats eventsreturned,evhandletimes;
	pthread_cond_t cond;
	pthread_mutex_t lock;
	// blocked: -1 for poller owns, 0 for unblocked, 1 for ctlthread
	int_fast32_t blocked_ctlthreads,blocked;
	uintmax_t exceptions,sigchldrx;
	// proof-of-concept implementation supports only one child at a time
	pid_t tracked_childpid;
	fdstatefxn childpid_callback;
	pthread_t tid;
} poller;

void inc_stateexceptions(void){
	++snarepoller->exceptions;
}

#define POLLERSIGNAL SIGURG

static int
flush_pfd_array(poller *p){
	int ret = 0,z;

	for(z = 0 ; z < p->pfds_available && p->pfds_active ; ++z){
		pollfd_state *fdstate = &p->fdstates[z];

		if(fdstate->pfd.fd >= 0){
			if(fdstate->freefxn){
				fdstate->freefxn(fdstate->state);
			}
			nag("Closing leftover fd %d\n",fdstate->pfd.fd);
			ret |= Close(fdstate->pfd.fd);
			--p->pfds_active;
			fdstate->state = NULL;
			fdstate->pfd.events = fdstate->pfd.revents = 0;
			fdstate->pfd.fd = -1;
		}
	}
	Free(p->fdstates);
	p->fdstates = NULL;
	return ret;
}

static inline int
handle_kqueue_read(poller *p,pollfd_state *state){
	typeof(state->rxfxn) rx;
	int ret = 0;

	// Other than POLLIN and POLLOUT, POLL flags are meaningless in .events
	// and unilaterally set in .revents.
	if((rx = state->rxfxn) == NULL){
		bitch("No RX callback on %d\n",state->pfd.fd);
		inc_stateexceptions();
	}else{
		// nag("RX callback %d\n",state->pfd.fd);
		++state->rxcbs;
		ret |= rx(p,state);
	}
	return ret;
}

static inline int
handle_kqueue_write(poller *p,pollfd_state *state){
	typeof(state->txfxn) tx;
	int ret = 0;

	// Other than POLLIN and POLLOUT, POLL flags are meaningless in .events
	// and unilaterally set in .revents.
	if((tx = state->txfxn) == NULL){
		bitch("No TX callback on %d\n",state->pfd.fd);
		inc_stateexceptions();
	}else{
		// nag("TX callback %d\n",state->pfd.fd);
		++state->txcbs;
		ret |= tx(p,state);
	}
	return ret;
}

static inline void
purge_fd_resulthandler(poller *p,pollfd_state *state,int fd){
	if(state->pfd.fd != fd){
		bitch("already killed fd %d\n",fd);
		inc_stateexceptions();
		return;
	}
	nag("Purging fd %d\n",fd);
	if(state->timerfd >= 0){
		nag("timerfd set: %d\n",state->timerfd);
		// state->timerfd == fd on fbsd
		if(del_timeout_from_pollqueue(p,fd)){
			inc_stateexceptions();
		}
	}
	if(state->freefxn){
		state->freefxn(state->state);
	}
	if(Close(fd)){
		inc_stateexceptions();
	}
	--p->pfds_active;
	memset(state,0,sizeof(*state));
	state->timerfd = -1;
	state->pfd.fd = -1;
}

static void
handle_sigchld(poller *p){
	int status;
	pid_t pid;

	if(p->tracked_childpid < 0){
		bitch("No child registered with poller\n");
		return;
	}
	// We don't want to listen to any child, or else handlers which
	// must use waitpid() will race aginst us. When we move to multiple
	// children, use the negation of the poller PID. Handlers can then
	// force a setpgid() if they need. FIXME
	if((pid = waitpid(p->tracked_childpid,&status,WNOHANG)) > 0){
		nag("Got SIGCHLD for PID %jd\n",(intmax_t)pid);
		p->childpid_callback(p,NULL);
		p->tracked_childpid = -1;
		p->childpid_callback = NULL;
	}
}

static int
handle_kqueue_error(const struct pollfd_state *state){
	socklen_t slen;
	int err;

       	slen = sizeof(err);
	if(Getsockopt(state->pfd.fd,SOL_SOCKET,SO_ERROR,&err,&slen)){
		return -1;
	}
	pmoan(err,"Socket error on %d\n",state->pfd.fd);
	return 0;
}

#ifdef POLLER_KQUEUE
// Parameters are taken from EV_SET (see kevent(2))
static int
enqueue_kqueue_change(poller *p,uintptr_t ident,short filter,u_short flags,
			u_int fflags,intptr_t data,void *udata){
	// This unlikely event could occur if, for instance, every fd is being
	// used, and on the last sysdep_poll() every one had event changes,
	// and then a verdict was injected while the poller was blocked.... or
	// (far more likely) in the case of programming error, heheh
	if(p->kchanges >= p->csize){
		typeof(p->csize) tmpcsize = p->csize * 2;
		typeof(*p->cv) *tmpcv;

		// If we've not yet been initialized, or reset, don't start
		// growing buffers...that's a serious problem. Should this be
		// changed, insert a p->csize check around the Kevent() failure
		// case involving vector dump and reuse of implied first slot!
		if(p->csize == 0){
			bitch("Used with uninitialized poller\n");
			return -1;
		}
		if((tmpcv = Realloc("kchange vector",p->cv,sizeof(*tmpcv) * tmpcsize)) == NULL){
			// If the realloc failed, dump the current vector...
			if(Kevent(p->kq,p->cv,p->kchanges,NULL,0,NULL)){
				inc_stateexceptions();
				return -1;
			}
			// Reinitialize the buffer. We're assured that there's
			// room for at least one of us now by p->csize check
			p->kchanges = 0;
		}else{
			p->cv = tmpcv;
			p->csize = tmpcsize;
		}
	}
	EV_SET(&p->cv[p->kchanges++],ident,filter,flags,fflags,data,udata);
	return 0;
}

static int
destroy_kqueue(poller *p){
	int ret = 0;

	ret |= Close(p->kq);
	p->kq = -1;
	Free(p->kv);
	p->kv = NULL;
	Free(p->cv);
	p->cv = NULL;
	p->kchanges = p->csize = p->ksize = 0;
	return ret;
}

static int
create_kqueue(poller *p){
	if(p->pfds_available <= 0){
		bitch("Poller's pfds weren't initialized\n");
		return -1;
	}
	p->ksize = p->pfds_available;
	p->csize = 2 * p->pfds_available;
	if((p->kv = Malloc("kqueue vector",sizeof(*p->kv) * p->ksize)) == NULL){
		return -1;
	}
	if((p->cv = Malloc("kchange vector",sizeof(*p->cv) * p->csize)) == NULL){
		Free(p->kv);
		return -1;
	}
	if((p->kq = kqueue()) < 0){
		Free(p->kv);
		Free(p->cv);
		return -1;
	}
	p->kchanges = 0;
	if(enqueue_kqueue_change(p,POLLERSIGNAL,EVFILT_SIGNAL,EV_ADD,0,0,NULL)){
		destroy_kqueue(p);
		return -1;
	}
	if(enqueue_kqueue_change(p,SIGCHLD,EVFILT_SIGNAL,EV_ADD,0,0,NULL)){
		destroy_kqueue(p);
		return -1;
	}
	return 0;
}

static int
handle_kqueue_timeout(struct poller *p,pollfd_state *state){
	typeof(state->timeoutfxn) tout = state->timeoutfxn;
	int ret = 0;

	if(tout == NULL){
		bitch("No timeout callback for POLLOUT on %d\n",state->pfd.fd);
	}else{
		ret |= tout(p,state);
	}
	return ret;
}

static void
handle_invalidated_kevent(const struct kevent *kv,int fd,pollfd_state *state){
	const char *etype;

	if(kv->filter == EVFILT_READ){
		etype = "read";
	}else if(kv->filter == EVFILT_WRITE){
		etype = "write";
	}else if(kv->filter == EVFILT_TIMER){
		etype = "timer";
	}else{
		etype = "unknown";
	}
	nag("%s %s on invalidated file descriptor %d (%d)\n",etype,
		(kv->flags & EV_ERROR) ? "error" : "event",fd,state->pfd.fd);
	// This should not be considered a state exception; it's an exepected,
	// if irregular, occurrence
}

// FIXME we need better EV_ERROR handling
static inline void
handle_kqueue_results(poller *p,const struct kevent *kevents,unsigned events){
	unsigned n = 0;

	// nag("Handling %u events\n",events);
	for(n = 0 ; n < events ; ++n){
		const struct kevent *kv = &kevents[n];

		if(kv->filter == EVFILT_SIGNAL){
			nag("SignalRX (%s)\n",strsignal(kv->ident));
			if(kv->ident == SIGCHLD){
				p->sigchldrx += kv->data;
				handle_sigchld(p);
			}
		}else{
			pollfd_state *state;
			int fd = kv->ident;

			if(fd < 0 || fd >= p->pfds_available){
				bitch("Invalid fd %d (max %d)\n",fd,p->pfds_available);
				inc_stateexceptions();
				continue;
			}
			state = &p->fdstates[fd];
			if(fd != state->pfd.fd){
				// We might close a descriptor despite
				// outstanding events later in the vector. Note
				// them, but don't take action otherwise.
				handle_invalidated_kevent(kv,fd,state);
			}else{
				struct timeval tvstart,tvend;
				int r;

				Gettimeofday(&tvstart,NULL);
				state->lastuse_time = tvstart.tv_sec;
				if(kv->flags & EV_ERROR){
					handle_kqueue_error(state);
					r = -1;
				}else if(kv->filter == EVFILT_READ){
					r = handle_kqueue_read(p,state);
				}else if(kv->filter == EVFILT_WRITE){
					r = handle_kqueue_write(p,state);
				}else if(kv->filter == EVFILT_TIMER){
					// nag("Timer callback %d\n",fd);
					r = handle_kqueue_timeout(p,state);
				}else{
					bitch("Unknown kevent filter %d\n",kv->filter);
					inc_stateexceptions();
					r = 0;
				}
				if(!r){
					time_avgmax(&state->pfd_avgmax_time,&tvend,&tvstart);
				}else{
					purge_fd_resulthandler(p,state,fd);
				}
			}
		}
	}
}

static int
addfd_to_kqueue(poller *p,const struct pollfd_submission *submsg){
	int flag,ret = 0;

	flag = (submsg->rxfxn ? EV_ENABLE : EV_DISABLE) | EV_CLEAR;
	ret |= enqueue_kqueue_change(p,submsg->fd,EVFILT_READ,EV_ADD | flag,0,0,NULL);
	flag = (submsg->txfxn ? EV_ENABLE : EV_DISABLE) | EV_CLEAR;
	ret |= enqueue_kqueue_change(p,submsg->fd,EVFILT_WRITE,EV_ADD | flag,0,0,NULL);
	return ret;
}
#else
#ifdef POLLER_EPOLL

// Parameters are taken from epoll_ctl (see epoll_ctl(2))
static int
enqueue_epoll_change(poller *p,int fd,int op,uint32_t events){
	struct epoll_event ev;

	memset(&ev,0,sizeof(ev));
	ev.events = events;
	ev.data.fd = fd;
	if(epoll_ctl(p->epfd,op,fd,&ev)){
		moan("Couldn't register %d with epoll\n",fd);
		return -1;
	}
	return 0;
}

// FIXME this is broken
#define EV_ERROR EPOLLERR
#define EV_ENABLE EPOLL_CTL_ADD
#define EV_DISABLE EPOLL_CTL_DEL
#define EV_DELETE EPOLL_CTL_DEL
#define EV_ADD EPOLL_CTL_ADD
#define enqueue_kqueue_change(p,fd,cmd,...) \
	enqueue_epoll_change(p,fd,EPOLL_CTL_MOD,pfd->events)

static int
addfd_to_kqueue(poller *p,const struct pollfd_submission *submsg){
	int events;

	events = (submsg->rxfxn ? POLLIN : 0) | (submsg->txfxn ? POLLOUT : 0) | EPOLLET;
	return enqueue_epoll_change(p,submsg->fd,EPOLL_CTL_ADD,events);
}

static int
stringize_signalfd(ustring *u,const pollfd_state *pfd __attribute__ ((unused))){
	if(printUString(u,"<signalfd/>") < 0){
		return -1;
	}
	return 0;
}

static int
stringize_timerfd(ustring *u,const pollfd_state *pfd __attribute__ ((unused))){
	if(printUString(u,"<timerfd/>") < 0){
		return -1;
	}
	return 0;
}

static int
signalfd_rx(poller *p,pollfd_state *pfd){
	struct signalfd_siginfo si;
	int ret;

	// We can't get partial reads on a signalfd; no need for Readn()
	while((ret = read(pfd->pfd.fd,&si,sizeof(si))) > 0){
		nag("Got %d bytes (%zu)\n",ret,sizeof(si));
		if(si.ssi_signo == SIGCHLD){
			++p->sigchldrx; // FIXME
			nag("SIGCHLD for pid %jd\n",(intmax_t)si.ssi_pid);
			handle_sigchld(p);
		}
		nag("Read signal %u (%s) on %d\n",si.ssi_signo,
				strsignal(si.ssi_signo),pfd->pfd.fd);
	}
	return 0; // don't want signalfd closed
}

static int
create_kqueue(poller *p){
	struct pollfd_submission pfds;
	sigset_t ss;

	if(p->pfds_available <= 0){
		bitch("Poller's pfds weren't initialized\n");
		return -1;
	}
	p->esize = p->pfds_available;
	if((p->ev = Malloc("epoll vector",sizeof(*p->ev) * p->esize)) == NULL){
		return -1;
	}
	if((p->epfd = epoll_create(p->esize)) < 0){
		Free(p->ev);
		p->ev = NULL;
		return -1;
	}
	if(set_fd_close_on_exec(p->epfd)){
		Close(p->epfd);
		p->epfd = -1;
		Free(p->ev);
		p->ev = NULL;
		return -1;
	}
	sigemptyset(&ss);
	sigaddset(&ss,SIGCHLD);
	sigaddset(&ss,POLLERSIGNAL);
	memset(&pfds,0,sizeof(pfds));
	if((pfds.fd = Signalfd(-1,&ss,SFD_CLOEXEC | SFD_NONBLOCK)) < 0){
		Close(p->epfd);
		p->epfd = -1;
		Free(p->ev);
		p->ev = NULL;
		return -1;
	}
	pfds.rxfxn = signalfd_rx;
	pfds.strfxn = stringize_signalfd;
	if(add_fd_to_pollqueue(p,&pfds,NULL,0)){
		Close(pfds.fd);
		Close(p->epfd);
		p->epfd = -1;
		Free(p->ev);
		p->ev = NULL;
		return -1;
	}
	return 0;
}

static int
Epoll_wait(int epfd,struct epoll_event *events,int maxevents,int timeout){
	int ret;

	if((ret = epoll_wait(epfd,events,maxevents,timeout)) < 0){
		if(errno != EINTR){
			moan("epoll_wait failed\n");
			abort();
			return -1;
		}
		nag("Interrupted by signal\n");
	}
	return ret;
}

static inline void
handle_epoll_results(poller *p,const struct epoll_event *evs,unsigned events){
	unsigned n = 0;

	// nag("Handling %u events\n",events);
	for(n = 0 ; n < events ; ++n){
		const struct epoll_event *ev = &evs[n];
		int fd = ev->data.fd;
		pollfd_state *state;

		if(fd < 0 || fd >= p->pfds_available){
			bitch("Invalid fd %d (max %d)\n",fd,p->pfds_available);
			inc_stateexceptions();
			continue;
		}
		state = &p->fdstates[fd];
		if(fd != state->pfd.fd){
			nag("Event on invalidated file descriptor %d (%d)\n",fd,state->pfd.fd);
			inc_stateexceptions();
		}else{
			struct timeval tvstart,tvend;
			int r = 0;

			Gettimeofday(&tvstart,NULL);
			state->lastuse_time = tvstart.tv_sec;
			// Linux sets EPOLLIN|EPOLLOUT together.
			if(ev->events & EPOLLIN){
				r |= handle_kqueue_read(p,state);
			}
			if(ev->events & EPOLLOUT && !r){
				r |= handle_kqueue_write(p,state);
			}
			if(ev->events & EPOLLHUP){ // output only
				// We needn't handle this explicitly; the TX
				// handler must be able to work independently
				// of this extraneous (but unmaskable) event...
				nag("fd %d hung up\n",fd);
				r = -1;
			}else if(ev->events & EPOLLERR){
				nag("EPOLLERR on fd %d\n",fd);
				handle_kqueue_error(state);
				r = -1;
			}else if(ev->events & ~(EPOLLIN|EPOLLOUT)){
				nag("unknown event (%d) on fd %d\n",ev->events,fd);
				r = -1;
			}
			if(!r){
				time_avgmax(&state->pfd_avgmax_time,&tvend,&tvstart);
			}else{
				purge_fd_resulthandler(p,state,fd);
			}
		}
	}
}

static inline int
destroy_kqueue(poller *p){
	int ret = 0;

	ret |= Close(p->epfd);
	p->epfd = -1;
	Free(p->ev);
	p->ev = NULL;
	p->esize = 0;
	return ret;
}

// FIXME this needs improvement, PoC only
typedef struct epoll_timer_wrapper_state {
	int fd;
	fdstatefxn timeoutfxn;
} epoll_timer_wrapper_state;

static int
epoll_timer_wrapper(poller *p,struct pollfd_state *pfd){
	epoll_timer_wrapper_state *ectx = (epoll_timer_wrapper_state *)pfd->state;
	uint64_t timercount;

	if(ectx == NULL){
		bitch("NULL callback\n");
		return -1;
	}
	if(Read(pfd->pfd.fd,&timercount,sizeof(timercount)) < 0){
		bitch("Couldn't read on timer %d->%d RX\n",pfd->pfd.fd,ectx->fd);
		return -1;
	}
	if(ectx->timeoutfxn(p,&p->fdstates[ectx->fd])){ // FIXME
		bitch("Error in timeout function\n");
		return -1;
	}
	return 0;
}

static void
epoll_timer_wrapper_freefxn(void *ectx){
	Free(ectx);
}
#endif
#endif

poller *create_poller(void){
	int maxfds,n;
	poller *ret;

	if((maxfds = determine_max_fds()) <= 0){
		return NULL;
	}
	if((ret = Malloc("poller",sizeof(*ret))) == NULL){
		return NULL;
	}
	memset(ret,0,sizeof(*ret));
	ret->pfds_available = maxfds;
	if((ret->fdstates = Malloc("fdstates",sizeof(*ret->fdstates) * maxfds)) == NULL){
		Free(ret);
		return NULL;
	}
	memset(ret->fdstates,0,sizeof(*ret->fdstates) * maxfds);
	for(n = 0 ; n < maxfds ; ++n){
		ret->fdstates[n].pfd.fd = -1;
	}
	if(create_kqueue(ret)){
		Free(ret->fdstates);
		Free(ret);
		return NULL;
	}
	if(Pthread_mutex_init("poller",&ret->lock)){
		Free(ret->fdstates);
		destroy_kqueue(ret);
		Free(ret);
		return NULL;
	}
	if(Pthread_cond_init("poller",&ret->cond)){
		Pthread_mutex_destroy("poller",&ret->lock);
		Free(ret->fdstates);
		destroy_kqueue(ret);
		Free(ret);
		return NULL;
	}
	return ret;
}

int destroy_poller(poller *p){
	int ret = 0;

	if(p){
		flush_pfd_array(p);
		ret |= Pthread_mutex_destroy("poller",&p->lock);
		ret |= Pthread_cond_destroy("poller",&p->cond);
		ret |= destroy_kqueue(p);
		Free((p)->fdstates);
		Free(p);
	}
	return ret;
}

static inline int
sysdep_poll(poller *p){
	struct timeval tvend,tvhandle;
	int ret;

#ifdef POLLER_KQUEUE
	if((ret = Kevent(p->kq,p->cv,p->kchanges,p->kv,p->ksize,NULL)) >= 0){
		p->kchanges = 0;
		Gettimeofday(&tvhandle,NULL);
		handle_kqueue_results(p,p->kv,ret);
		time_avgmax(&p->evhandletimes,&tvend,&tvhandle);
		adjust_avgmax_stats(&p->eventsreturned,ret);
	}else{
		inc_stateexceptions();
	}
#else
#ifdef POLLER_EPOLL
	if((ret = Epoll_wait(p->epfd,p->ev,p->esize,-1)) >= 0){
		Gettimeofday(&tvhandle,NULL);
		handle_epoll_results(p,p->ev,ret);
		time_avgmax(&p->evhandletimes,&tvend,&tvhandle);
		adjust_avgmax_stats(&p->eventsreturned,ret);
	}else{
		inc_stateexceptions();
	}
#else
	bitch("No polling mechanism defined\n");
	ret = -1;
#endif
#endif
	return ret;
}

void set_pollertid_hack(poller *p){
	p->tid = pthread_self();
}

void run_poller(poller *p){
	// Check to see if there's any client threads blocked or running. Let
	// them work until they're done. The pthread_testcancel() must provide
	// our thread's only cancellation point, or else threads waiting on the
	// lock might never get it: cancellation ought be disabled on entry!
	pthread_mutex_lock(&p->lock);
	if(p->blocked == -1){
		p->blocked = 0;
	}
	while(p->blocked_ctlthreads){
		pthread_cond_broadcast(&p->cond);
		pthread_cond_wait(&p->cond,&p->lock);
	}
	p->blocked = -1;
	pthread_mutex_unlock(&p->lock);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,NULL);
	pthread_testcancel();
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,NULL);
	sysdep_poll(p); // leave cancellation disabled; see comment above
}

int enable_fd_rx(pollfd_state *state,fdstatefxn fxn){
	struct pollfd *pfd = &state->pfd;

	// nag("ENABLE RX %d\n",pfd->fd);
	state->rxfxn = fxn;
	if( (pfd->events & POLLIN) ){
		bitch("Fd %d was already set for RX\n",pfd->fd);
		inc_stateexceptions();
		return -1;
	}
	pfd->events |= POLLIN;
	return enqueue_kqueue_change(snarepoller,pfd->fd,EVFILT_READ,EV_ENABLE,0,0,NULL);
}

int enable_fd_tx(pollfd_state *state,fdstatefxn fxn){
	struct pollfd *pfd = &state->pfd;

	// nag("ENABLE TX %d\n",pfd->fd);
	state->txfxn = fxn;
	if( (pfd->events & POLLOUT) ){
		bitch("pfd->fd %d was already set for TX\n",pfd->fd);
		inc_stateexceptions();
		return -1;
	}
	pfd->events |= POLLOUT;
	return enqueue_kqueue_change(snarepoller,pfd->fd,EVFILT_WRITE,EV_ENABLE,0,0,NULL);
}

int disable_fd_rx(pollfd_state *state){
	struct pollfd *pfd = &state->pfd;

	// nag("DISABLE RX %d\n",pfd->fd);
	state->rxfxn = NULL;
	if(!(pfd->events & POLLIN)){
		bitch("pfd->fd %d wasn't set for RX\n",pfd->fd);
		inc_stateexceptions();
		return -1;
	}
	pfd->events &= ~POLLIN;
	return enqueue_kqueue_change(snarepoller,pfd->fd,EVFILT_READ,EV_DISABLE,0,0,NULL);
}

int disable_fd_tx(pollfd_state *state){
	struct pollfd *pfd = &state->pfd;

	// nag("DISABLE TX %d\n",pfd->fd);
	state->txfxn = NULL;
	if(!(pfd->events & POLLOUT)){
		bitch("pfd->fd %d wasn't set for TX\n",pfd->fd);
		inc_stateexceptions();
		return -1;
	}
	pfd->events &= ~POLLOUT;
	return enqueue_kqueue_change(snarepoller,pfd->fd,EVFILT_WRITE,EV_DISABLE,0,0,NULL);
}

// We want the fd for which the timer is registered, *not* the "timerfd" (this
// concept is only meaningful on Linux -- on FreeBSD, we've got EV_TIMER using
// the original fd as its event id).
int del_timeout_from_pollqueue(poller *p,int fd){
	typeof(*p->fdstates) *fdstate,*tfdstate;

	if(fd < 0 || fd >= p->pfds_available){
		bitch("Invalid fd %d (max %d)\n",fd,p->pfds_available);
		return -1;
	}
	fdstate = &p->fdstates[fd];
	if(fdstate->timerfd < 0){
		bitch("No timerfd set for fd %d\n",fd);
		return -1;
	}
	tfdstate = &p->fdstates[fdstate->timerfd];
#ifdef POLLER_KQUEUE
	nag("Shutting down timer for %d\n",fd);
	tfdstate->timeoutfxn = NULL;
	if(enqueue_kqueue_change(p,fd,EVFILT_TIMER,EV_DELETE,0,0,NULL)){
		return -1;
	}
#else
#ifdef POLLER_EPOLL
	nag("Shutting down timerfd %d for %d\n",fdstate->timerfd,fd);
	purge_fd_resulthandler(p,tfdstate,fdstate->timerfd);
#else
	bitch("Timeouts are not supported on this OS (for %d in %p)\n",fd,p);
	return -1;
#endif
#endif
	fdstate->timerfd = -1;
	return 0;
}

int add_child_to_pollqueue(poller *p,pid_t pid,fdstatefxn sigfxn){
	if(p == NULL || sigfxn == NULL){
		bitch("NULL poller / sigfxn\n");
		return -1;
	}
	if(pid <= 0){ // init cannot be our child
		bitch("Invalid PID: %jd\n",(intmax_t)pid);
		return -1;
	}
	if(p->tracked_childpid > 0){
		bitch("PID %jd is already being tracked\n",(intmax_t)p->tracked_childpid);
		return -1;
	}
	nag("Registered child PID %jd\n",(intmax_t)pid);
	p->tracked_childpid = pid;
	p->childpid_callback = sigfxn;
	return 0;
}

int add_timeout_to_pollqueue(poller *p,int msec,int fd,fdstatefxn timeoutfxn){
	typeof(*p->fdstates) *fdstate;

	if(p == NULL || timeoutfxn == NULL){
		bitch("NULL poller / timeoutfxn\n");
		return -1;
	}
	if(fd < 0 || fd >= p->pfds_available){
		bitch("Invalid fd %d (max %d)\n",fd,p->pfds_available);
		return -1;
	}
	fdstate = &p->fdstates[fd];
	if(fd != fdstate->pfd.fd){
		bitch("Invalid fd (%d != %d)\n",fd,fdstate->pfd.fd);
		return -1;
	}
#ifdef POLLER_KQUEUE
	if(enqueue_kqueue_change(p,fd,EVFILT_TIMER,EV_ADD,0,msec,NULL)){
		return -1;
	}
	fdstate->timeoutfxn = timeoutfxn;
	fdstate->timerfd = fd;
	nag("Set %dms kqueue timer for %d\n",msec,fd);
#else
#ifdef POLLER_EPOLL
	{
	epoll_timer_wrapper_state *ectx;
	struct pollfd_submission pfds;
	struct itimerspec ispec;
	int newfd;

	if((newfd = Timerfd_create(CLOCK_MONOTONIC,TFD_NONBLOCK | TFD_CLOEXEC)) < 0){
		inc_stateexceptions();
		return -1;
	}
	if((ectx = Malloc("epoll timer hack",sizeof(*ectx))) == NULL){
		Close(newfd);
		return -1;
	}
	ispec.it_value.tv_sec = msec / 1000;
	ispec.it_value.tv_nsec = (msec % 1000) * 1000000;
	ispec.it_interval.tv_sec = msec / 1000;
	ispec.it_interval.tv_nsec = (msec % 1000) * 1000000;
	if(Timerfd_settime(newfd,0,&ispec,NULL)){
		Close(newfd);
		Free(ectx);
		return -1;
	}
	memset(&pfds,0,sizeof(pfds));
	pfds.rxfxn = epoll_timer_wrapper;
	pfds.fd = newfd;
	ectx->timeoutfxn = timeoutfxn;
	ectx->fd = fd;
	pfds.state = ectx;
	pfds.freefxn = epoll_timer_wrapper_freefxn;
	pfds.strfxn = stringize_timerfd;
	if(add_fd_to_pollqueue(p,&pfds,NULL,0)){
		Close(newfd);
		Free(ectx);
		return -1;
	}
	fdstate->timerfd = newfd;
	nag("Set %dms interval timer for %d on %d\n",msec,fd,newfd);
	}
#else
	bitch("Timeouts are not supported on this OS (for %d in %p using %p/%dms)\n",
			fd,p,timeoutfxn,msec);
	return -1;
#endif
#endif
	return 0;
}

// FIXME what if: event A0 closes fd N, event A1 spawns a new fd (and gets N),
// adding it, and then event A2 references fd N? we'll process a phantom event
// on that fd, which will likely work just fine (actually a bit less latent,
// but more cpu usage overall due to a wasted syscall), but possibly break due
// to no proper callback defined, or the scheduled ADD being invalidated via
// processing's completion on the fd
int add_fd_to_pollqueue(poller *p,const struct pollfd_submission *submsg,
			const struct sockaddr *sa,socklen_t slen){
	typeof(*p->fdstates) *fdstate;
	typeof(fdstate->pfd) *newpfd;

	if(submsg == NULL || p == NULL){
		bitch("NULL submission / poller\n");
		return -1;
	}
	if(sa){
		if(slen == 0){
			bitch("Invalid 0 length for non-NULL sa\n");
			return -1;
		}else if(slen > sizeof(fdstate->peer)){
			bitch("Socklen too large (%u > %zu)\n",slen,sizeof(fdstate->peer));
			return -1;
		}
	}else if(slen){
		bitch("Invalid non-0 length (%u) for NULL sa\n",slen);
		return -1;
	}
	// nag("adding %d\n",submsg->fd);
	if(submsg->fd < 0 || submsg->fd >= p->pfds_available){
		bitch("Invalid fd %d (max %d)\n",submsg->fd,p->pfds_available);
		return -1;
	}
	fdstate = &p->fdstates[submsg->fd];
	if(fdstate->pfd.fd != -1){
		bitch("Already using fd %d\n",fdstate->pfd.fd);
		return -1;
	}
	newpfd = &fdstate->pfd;
	if(addfd_to_kqueue(p,submsg)){
		return -1;
	}
	if(++p->pfds_active > p->max_pfds_active){
		p->max_pfds_active = p->pfds_active;
		nag("New active pfd max: %u (on fd %d)\n",p->max_pfds_active,submsg->fd);
	}
	if(sa){
		memcpy(&fdstate->peer,sa,slen);
	}else{
		memset(&fdstate->peer,0,sizeof(fdstate->peer));
	}
	fdstate->txcbs = fdstate->rxcbs = 0;
	fdstate->lastuse_time = fdstate->creation_time = time(NULL);
	newpfd->events = 0;
	newpfd->events |= (fdstate->rxfxn = submsg->rxfxn) ? POLLIN : 0;
	newpfd->events |= (fdstate->txfxn = submsg->txfxn) ? POLLOUT : 0;
	fdstate->freefxn = submsg->freefxn;
	fdstate->strfxn = submsg->strfxn;
	fdstate->timerfd = -1;
	newpfd->revents = 0;
	newpfd->fd = submsg->fd;
	fdstate->state = submsg->state;
	return 0;
}

int close_pollqueue_fd(poller *p,int fd){
	pollfd_state *state;

	if(fd < 0 || fd >= p->pfds_available){
		bitch("Invalid fd %d (max %d)\n",fd,p->pfds_available);
		inc_stateexceptions();
		return -1;
	}
	state = &p->fdstates[fd];
	purge_fd_resulthandler(p,state,fd); // FIXME get result code
	return 0;
}

// Ought enter with cancellation disabled
int block_poller(poller *p){
	int ret = 0;

	if(p){
		if( (errno = pthread_mutex_lock(&p->lock)) ){
			moan("Couldn't take polllock\n");
			return -1;
		}
		++p->blocked_ctlthreads;
		// if poller thread is cancelled, p->blocked will be left as
		// -1, and we'd be deadlocked. in that case, though, the
		// signal_poller() operation will fail, and we break out.
		while(p->blocked){
			if(signal_poller(p)){
				ret = -1;
				break;
			}
			pthread_cond_wait(&p->cond,&p->lock);
		}
		if(ret == 0){
			p->blocked = 1;
		}else{
			--p->blocked_ctlthreads;
		}
		pthread_mutex_unlock(&p->lock);
	}
	return ret;
}

int unblock_poller(poller *p){
	int ret = 0;

	if(p){
		if( (errno = pthread_mutex_lock(&p->lock)) ){
			moan("Couldn't take polllock\n");
			ret = -1;
		}else{
			p->blocked = 0;
			--p->blocked_ctlthreads;
			ret |= pthread_cond_broadcast(&p->cond);
			ret |= pthread_mutex_unlock(&p->lock);
		}
	}
	return ret;
}

int signal_poller(poller *p){
	nag("signaling poller\n");
	if(p->tid){
		if( (errno = pthread_kill(p->tid,POLLERSIGNAL)) ){
			moan("Couldn't signal poller\n");
			return -1;
		}
	}else{
		nag("No poller thread\n");
	}
	nag("signaled poller\n");
	return 0;
}

static int
stringize_pfd(ustring *u,const struct pollfd *pfd,const struct pollfd_state *s){
	time_t now = time(NULL);

	if(printUString(u,"<pfd>%s%s%s<fd>%d</fd><age>%.0f</age><idle>%.0f</idle>"
			"<handleus><avg>%ju</avg><max>%ju</max></handleus>"
			"<rxcbs>%u</rxcbs><txcbs>%u</txcbs>",
				(pfd->events & POLLIN) ? "<in/>" : "",
				(pfd->events & POLLOUT) ? "<out/>" : "",
				s->timeoutfxn ? "<timer/>" : "",
				pfd->fd,
				difftime(now,s->creation_time),
				difftime(now,s->lastuse_time),
				s->pfd_avgmax_time.avg,s->pfd_avgmax_time.max,
				s->rxcbs,s->txcbs) < 0){
		return -1;
	}
	if(s->strfxn){
		if(s->strfxn(u,s) < 0){
			return -1;
		}
	}
	if(printUString(u,"</pfd>") < 0){
		return -1;
	}
	return 0;
}

int stringize_pfds_locked(const poller *p,ustring *u){
	int z;

	if(printUString(u,"<pfd_state>") < 0){
		return -1;
	}
	for(z = 0 ; z < p->pfds_available ; ++z){
		if(p->fdstates[z].pfd.fd < 0){
			continue;
		}
		if(stringize_pfd(u,&p->fdstates[z].pfd,&p->fdstates[z]) < 0){
			return -1;
		}
	}
	if(printUString(u,"<maxactivefds>%u</maxactivefds>",p->max_pfds_active) < 0){
		return -1;
	}
	if(printUString(u,"<activefds>%u</activefds>",p->pfds_active) < 0){
		return -1;
	}
	if(printUString(u,"<handlerus><avg>%ju</avg><max>%ju</max></handlerus>",
			p->evhandletimes.avg,p->evhandletimes.max) < 0){
		return -1;
	}
	if(printUString(u,"<sigchldrx>%ju</sigchldrx>",p->sigchldrx) < 0){
		return -1;
	}
	if(printUString(u,"<exceptions>%ju</exceptions>",p->exceptions) < 0){
		return -1;
	}
	if(printUString(u,"<events><avg>%ju</avg><max>%ju</max></events>",
			p->eventsreturned.avg,p->eventsreturned.max) < 0){
		return -1;
	}
	if(printUString(u,"</pfd_state>") < 0){
		return -1;
	}
	return 0;
}

const void *get_const_pfd_state(const pollfd_state *pfd){
	return pfd->state;
}

void *get_pfd_state(pollfd_state *pfd){
	return pfd->state;
}

int set_poller_sigmask(void){
	sigset_t ss;

	sigemptyset(&ss);
	sigaddset(&ss,SIGCHLD);
	sigaddset(&ss,POLLERSIGNAL);
	if(Sigprocmask(SIG_BLOCK,&ss,NULL)){
		return -1;
	}
	return 0;
}

int unset_poller_sigmask(void){
	sigset_t ss;

	sigemptyset(&ss);
	sigaddset(&ss,SIGCHLD);
	sigaddset(&ss,POLLERSIGNAL);
	if(Sigprocmask(SIG_UNBLOCK,&ss,NULL)){
		return -1;
	}
	return 0;
}

int stringize_sdbuf_sizes(ustring *u,int sd){
	int bufsiz;

	if(get_socket_rcvbuf(sd,&bufsiz) == 0){
		if(printUString(u,"<rbuf>%d</rbuf>",bufsiz) < 0){
			return -1;
		}
	}
	if(get_socket_sndbuf(sd,&bufsiz) == 0){
		if(printUString(u,"<sbuf>%d</sbuf>",bufsiz) < 0){
			return -1;
		}
	}
	return 0;
}
