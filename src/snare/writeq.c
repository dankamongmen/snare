#include <unistd.h>
#include <string.h>
#include <snare/oqueue.h>
#include <snare/writeq.h>
#include <libdank/utils/fds.h>
#include <snare/icap/request.h>
#include <libdank/ersatz/compat.h>
#include <libdank/utils/syswrap.h>
#include <libdank/utils/memlimit.h>
#include <libdank/objects/logctx.h>

typedef enum {
	PENDING_MSG_USTRING,
	PENDING_MSG_OKEY,
	PENDING_MSG_COUNT
} pending_msg_types;

typedef struct pending_msg {
	union {
		ustring u;
		oqueue_key *okey;
	} content;
	off_t off;	// virtual offset (see libdank/utils/mmap.h)
	size_t tosend;
	pending_msg_types mtype;
	struct pending_msg *next;
} pending_msg;

void init_writeq(writeq *wq){
	memset(wq,0,sizeof(*wq));
}

static void
free_pending_msg(pending_msg **pm){
	if(pm && *pm){
		switch((*pm)->mtype){
			case PENDING_MSG_USTRING:
				reset_ustring(&(*pm)->content.u);
				break;
			case PENDING_MSG_OKEY:
				break;
			case PENDING_MSG_COUNT: default:
				bitch("Asked to free type %d\n",(*pm)->mtype);
				break;
		}
		Free(*pm);
		*pm = NULL;
	}
}

// Suitable for edge-triggered event handling without signal-driven control
// flows (we arbitrarily loop on EINTR). sendfile(2) is used for file-backed
// maps, write(2) otherwise, but fallback from sendfile(2) errors to write(2)
// is not implemented.
static int
txfile(int sd,pending_msg *pm){
	ssize_t ret;

	do{ // precondition: amount to send > 0
		off_t oldoff = pm->off;

		/*if(pm->content.okey->fd >= 0){
			nag("%zu SENDFILE from %d to %d\n",pm->tosend,pm->content.okey->fd,sd);
			ret = sendfile_compat(sd,pm->content.okey->fd,&pm->off,pm->tosend);
		}else{*/
			//nag("%zu WRITE from %p to %d\n",pm->tosend,pm->content.okey->buf,sd);
			ret = write(sd,oqueue_const_ptrto(pm->content.okey,pm->off),
						pm->tosend);
			if(ret >= 0){
				pm->off += ret;
			}
		// }
		pm->tosend -= pm->off - oldoff;
		if(ret < 0){
			if(errno == EAGAIN || errno == EWOULDBLOCK){
				return WRITEQ_RES_NBLOCK;
			}else if(errno != EINTR){ // loop on EINTR
				moan("Error during %jd@%zu tx on %d\n",(intmax_t)pm->off,pm->tosend,sd);
				return WRITEQ_RES_SYSERR;
			}
		}
	}while(pm->tosend);
	if(pm->content.okey->cbarg){
		if(icap_state_verdictp(get_const_pfd_state(pm->content.okey->cbarg))){
			if(window_icap_encapsulate(pm->content.okey,pm->off)){
				return WRITEQ_RES_SYSERR;
			}
		}
	}
	return WRITEQ_RES_SUCCESS;
}

static writeq_res
txstr(int sd,pending_msg *pm){
	ssize_t ret;

	do{ // precondition: amount to send > 0
	// loop around possible EINTRs
		if((ret = write(sd,pm->content.u.string + pm->off,pm->tosend)) < 0){
			if(errno == EAGAIN || errno == EWOULDBLOCK){
				return WRITEQ_RES_NBLOCK;
			}else if(errno != EINTR){ // loop on eintr
				moan("Error writing %zud on %d\n",pm->tosend,sd);
				return WRITEQ_RES_SYSERR;
			}
		}else{
			pm->off += ret;
			pm->tosend -= ret;
		}
	}while(pm->tosend);
	return WRITEQ_RES_SUCCESS;
}

static writeq_res
write_pending_msg(int sd,pending_msg *pm){
	if(pm->mtype == PENDING_MSG_OKEY){
		return txfile(sd,pm);
	}else if(pm->mtype == PENDING_MSG_USTRING){
		return txstr(sd,pm);
	}
	return WRITEQ_RES_SYSERR;
}

writeq_res send_writeq_data(writeq *wq,int sd){
	writeq_res res = WRITEQ_RES_SUCCESS;

	if(cork_fd(sd)){
		return -1;
	}
	while(wq->pmlist){
		if((res = write_pending_msg(sd,wq->pmlist)) == WRITEQ_RES_SUCCESS){
			pending_msg *tmp;

			tmp = wq->pmlist;
			if((wq->pmlist = tmp->next) == NULL){
				wq->lastpm = NULL;
			}
			free_pending_msg(&tmp);
		}else{
			break;
		}
	}
	if(uncork_fd(sd)){
		return -1;
	}
	return res;
}

static pending_msg *
create_pending_msgbuf(const char *fmt,va_list va){
	pending_msg *pm;
	int ret;

	if((pm = Malloc("pmsg-str",sizeof(*pm))) == NULL){
		return NULL;
	}
	init_ustring(&pm->content.u);
	if((ret = vprintUString(&pm->content.u,fmt,va)) < 0){
		free_pending_msg(&pm);
		return NULL;
	}
	pm->off = 0;
	pm->mtype = PENDING_MSG_USTRING;
	pm->tosend = ret;
	return pm;
}

static pending_msg *
create_pending_msg_okey(struct oqueue_key *okey,off_t off,size_t s){
	pending_msg *pm;

	if((pm = Malloc("pmsg-okey",sizeof(*pm))) == NULL){
		return NULL;
	}
	pm->mtype = PENDING_MSG_OKEY;
	pm->content.okey = okey;
	pm->off = off;
	pm->tosend = s;
	return pm;
}

static void
enqueue_writer_msg(writeq *wq,pending_msg *pm){
	if(wq->lastpm){
		wq->lastpm->next = pm;
	}else{
		wq->pmlist = pm;
	}
	wq->lastpm = pm;
	pm->next = NULL;
}

int writeq_sendfile(writeq *wq,struct oqueue_key *okey,off_t off,off_t len){
	pending_msg *pm;

	if(len < 0){
		bitch("Cannot enqueue %lldb file @%lld\n",(long long)len,(long long)off);
		return -1;
	}else if(len == 0){
		return 0;
	}else if(sizeof(len) > sizeof(size_t)){
		if(len > (typeof(len))SSIZE_MAX){
			bitch("%lld > %lld\n",(long long)len,(long long)(typeof(len))SSIZE_MAX);
			return -1;
		}
	}
	if((pm = create_pending_msg_okey(okey,off,(size_t)len)) == NULL){
		return -1;
	}
	enqueue_writer_msg(wq,pm);
	return 0;
}

int writeq_printf(writeq *wq,const char *fmt,...){
	pending_msg *pm;
	va_list va;
	int ret;

	if((pm = wq->lastpm) && pm->mtype == PENDING_MSG_USTRING){
		va_start(va,fmt);
		ret = vprintUString(&pm->content.u,fmt,va);
		va_end(va);
		if(ret <= 0){
			return -1;
		}
		pm->tosend += ret;
		ret = 0;
	}else{
		va_start(va,fmt);
		pm = create_pending_msgbuf(fmt,va);
		va_end(va);
		if(pm){
			enqueue_writer_msg(wq,pm);
			ret = 0;
		}else{
			ret = -1;
		}
	}
	return ret;
}

static void
flush_pending_msgs(pending_msg **pm){
	pending_msg *tmp;
	unsigned n = 0;

	while( (tmp = *pm) ){
		*pm = tmp->next;
		free_pending_msg(&tmp);
		++n;
	}
	if(n){
		nag("Flushed %u unused msgs\n",n);
	}
}

void reset_writeq(writeq *wq){
	flush_pending_msgs(&wq->pmlist);
	wq->lastpm = NULL;
}
