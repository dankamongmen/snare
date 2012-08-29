#include <sys/wait.h>
#include <sys/poll.h>
#include <netinet/tcp.h>
#include <snare/oqueue.h>
#include <snare/server.h>
#include <snare/poller.h>
#include <snare/version.h>
#include <snare/pollinbuf.h>
#include <snare/icap/stats.h>
#include <libdank/utils/fds.h>
#include <snare/icap/request.h>
#include <libdank/utils/time.h>
#include <snare/icap/response.h>
#include <libdank/utils/netio.h>
#include <libdank/utils/maxfds.h>
#include <libdank/utils/string.h>
#include <libdank/utils/syswrap.h>
#include <libdank/utils/memlimit.h>
#include <libdank/objects/portset.h>
#include <libdank/modules/ctlserver/ctlserver.h>

static time_t starttime;
struct poller * restrict snarepoller;

static void
free_icap_state_wrapper(void *v){
	free_icap_state(v);
}

static int
stringize_icap_state_wrapper(ustring *u,const pollfd_state *pfd){
	if(printUString(u,"<icap>") < 0){
		return -1;
	}
	if(stringize_sdbuf_sizes(u,pfd->pfd.fd)){
		return -1;
	}
	if(stringize_icap_state(u,get_const_pfd_icap(pfd))){
		return -1;
	}
	if(printUString(u,"</icap>") < 0){
		return -1;
	}
	return 0;
}

static int
stringize_icap_server_wrapper(ustring *u,const pollfd_state *pfd
						__attribute__ ((unused))){
	struct sockaddr_storage ss;
	const char *family;
	socklen_t slen;

	slen = sizeof(ss);
	if(Getsockname(pfd->pfd.fd,(struct sockaddr *)&ss,&slen)){
		return -1;
	}
	switch(ss.ss_family){
		case AF_INET: family = "ipv4"; break;
		case AF_INET6: family = "ipv6"; break;
		default:
		bitch("Don't know address family %d\n",ss.ss_family);
		return -1;
	}
	if(printUString(u,"<icapsrv><%s/></icapsrv>",family) < 0){
		return -1;
	}
	return 0;
}

static int
icap_accept(struct poller *p,pollfd_state *pfd){
	struct sockaddr_storage sina;
	socklen_t slen;
	int sd;

	// ugh...we use a continue deep within the loop to jump back here, since we
	// must keep accept()ing until error under edge-triggering rules.
	while(1){
		slen = sizeof(sina);
		memset(&sina,0,sizeof(sina));
		while((sd = accept(pfd->pfd.fd,(struct sockaddr *)&sina,&slen)) < 0){
			if(errno == EAGAIN || errno == EWOULDBLOCK){
				return 0;
			}else if(errno != EINTR){
				moan("Error accepting on %d\n",pfd->pfd.fd);
				return -1; // FIXME reopen accepting socket
			} // loop on EINTR
		}
		inc_connections();
		if(!set_fd_nonblocking(sd) && !set_fd_close_on_exec(sd)){
			struct pollfd_submission submsg;

			memset(&submsg,0,sizeof(submsg));
			if( (submsg.state = create_icap_state()) ){
				submsg.fd = sd;
				submsg.rxfxn = pollinbuf_cb;
				submsg.txfxn = icap_tx_callback;
				submsg.freefxn = free_icap_state_wrapper;
				submsg.strfxn = stringize_icap_state_wrapper;
				nag("New ICAP connection on %d\n",sd);
				if(!add_fd_to_pollqueue(p,&submsg,(const struct sockaddr *)&sina,sizeof(sina))){
					continue;
				}
				free_icap_state(submsg.state);
			}
		}
		// We couldn't add the fd; close it back up (but try accepting again!)
		Close(sd);
	}
	return 0;
}

static inline int
filter_listener_dataready(int sd){
#ifdef SO_ACCEPTFILTER
	struct accept_filter_arg afa = { .af_name = "dataready", };

	return Setsockopt(sd,SOL_SOCKET,SO_ACCEPTFILTER,&afa,sizeof(afa));
#else
	int secs = 10;

	return Setsockopt(sd,IPPROTO_TCP,TCP_DEFER_ACCEPT,&secs,sizeof(secs));
#endif
}

static int
setup_icap_listener(struct poller *p,const struct sockaddr *sa,socklen_t slen){
	struct pollfd_submission submsg;
	int sd;

	// FIXME this ought be based off delay-bandwidth product, based off
	// link speed lookup (libdank can do this) and...
	if((sd = make_listener(sa,slen,0)) < 0){
		return -1;
	}
	if(filter_listener_dataready(sd)){
		return -1;
	}
	if(set_fd_nonblocking(sd) || set_fd_close_on_exec(sd)){
		Close(sd);
		return -1;
	}
	memset(&submsg,0,sizeof(submsg));
	submsg.fd = sd;
	submsg.rxfxn = icap_accept;
	submsg.strfxn = stringize_icap_server_wrapper;
	if(add_fd_to_pollqueue(p,&submsg,sa,slen)){
		Close(sd);
		return -1;
	}
	return 0;
}

static int
stringize_snare(ustring *u){
	time_t curtime;

	if((curtime = time(NULL)) < 0){
		bitch("Couldn't look up current time\n");
		return -1;
	}
#define SNARE_BASE_TAG "snare"
	if(printUString(u,"<"SNARE_BASE_TAG">") < 0){
		return -1;
	}
#define SNARE_VERSION_TAG "ver"
	if(printUString(u,"<"SNARE_VERSION_TAG">%s-r%s</"SNARE_VERSION_TAG">",
				Version,REVISION) < 0){
		return -1;
	}
#undef SNARE_COMPILER_TAG
#define SNARE_COMPILER_TAG "compiler"
	if(printUString(u,"<"SNARE_COMPILER_TAG">%s</"SNARE_COMPILER_TAG">",Compiler) < 0){
		return -1;
	}
#undef SNARE_COMPILER_TAG
#define CURTIME_TAG "age"
	if(printUString(u,"<"CURTIME_TAG">%jd</"CURTIME_TAG">",(intmax_t)(curtime - starttime)) < 0){
		return -1;
	}
#undef CURTIME_TAG
	if(printUString(u,"</"SNARE_BASE_TAG">") < 0){
		return -1;
	}
#undef SNARE_BASE_TAG
	return 0;
}

static int
srv_snare_dump(cmd_state *cs __attribute__ ((unused))){
	int ret = -1;
	logctx *lc;

	if((lc = get_thread_logctx()) == NULL){
		return ret;
	}
	ret = stringize_snare(lc->out);
	return ret;
}

static int
srv_pfds_enum(cmd_state *cs __attribute__ ((unused))){
	int ret = -1;
	logctx *lc;

	if((lc = get_thread_logctx()) == NULL){
		return ret;
	}
	block_poller(snarepoller);
	ret = stringize_pfds_locked(snarepoller,lc->out);
	unblock_poller(snarepoller);
	return ret;
}

static const command commands[] = {
	{ .cmd = "snare_dump",		.func = srv_snare_dump,		},
	{ .cmd = "pfd_table_dump",	.func = srv_pfds_enum,		},
	{ .cmd = NULL,			.func = NULL,			}
};

int start_icap_servers(uint16_t port){
	struct sockaddr_in6 sina6;
	struct sockaddr_in sina;

	starttime = time(NULL);
	memset(&sina6,0,sizeof(sina6));
	sina6.sin6_family = AF_INET6;
	memcpy(&sina6.sin6_addr,&in6addr_any,sizeof(sina6.sin6_addr));
	sina6.sin6_port = htons(port);
	memset(&sina,0,sizeof(sina));
	sina.sin_family = AF_INET;
	sina.sin_addr.s_addr = htonl(INADDR_ANY);
	sina.sin_port = htons(port);
	if(setup_icap_listener(snarepoller,(const struct sockaddr *)&sina,sizeof(sina))){
		return -1;
	}
	if(setup_icap_listener(snarepoller,(const struct sockaddr *)&sina6,sizeof(sina6))){
		if(errno != EAFNOSUPPORT){ // FIXME
			return -1;
		}
	}
	if(regcommands(commands)){
		return -1;
	}
	return 0;
}

int close_icap_servers(void){
	int ret = 0;

	ret |= delcommands(commands);
	return ret;
}
