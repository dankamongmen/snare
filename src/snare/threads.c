#include <snare/poller.h>
#include <snare/threads.h>
#include <libdank/modules/tracing/threads.h>

static pthread_t polltid;
static pthread_t *pollthread_active;
static pthread_mutex_t pmutex = PTHREAD_MUTEX_INITIALIZER;

static void
poller_main(void *poller){
	struct poller *p = poller;

	set_pollertid_hack(p);
	for( ; ; ){
		run_poller(p);
	}
}

int launch_poller_thread(struct poller *p){
	int ret;

	if(pthread_mutex_lock(&pmutex)){
		return -1;
	}
	// FIXME create it with cancellation disabled (see run_poller())
	if((ret = new_traceable_thread("poller",&polltid,poller_main,p)) == 0){
		pollthread_active = &polltid;
	}
	ret |= pthread_mutex_unlock(&pmutex);
	return ret;
}

int reap_poller_thread(struct poller *p){
	pthread_t *active;
	int ret = 0;

	if(pthread_mutex_lock(&pmutex)){
		return -1;
	}
	active = pollthread_active;
	pollthread_active = NULL;
	ret |= pthread_mutex_unlock(&pmutex);
	if(active){
		ret |= Pthread_cancel(*active);
		ret |= signal_poller(p);
		ret |= join_traceable_thread("poller",*active);
	}
	return ret;
}

int block_all_pollers(void){
	if(block_poller(snarepoller)){
		return -1;
	}
	return 0;
}

int unblock_all_pollers(void){
	if(unblock_poller(snarepoller)){
		return -1;
	}
	return 0;
}
