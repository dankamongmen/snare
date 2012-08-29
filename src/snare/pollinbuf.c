#include <unistd.h>
#include <snare/oqueue.h>
#include <snare/pollinbuf.h>
#include <snare/icap/request.h>
#include <libdank/utils/syswrap.h>
#include <libdank/utils/memlimit.h>
#include <libdank/objects/crlfreader.h>

typedef enum {
	BLOB_READ_SUCCESS,
	// We never read more than we want, but we still need go finish out the
	// POLLIN's worth of reading on a fulfilled request, or on fulfillment
	// from previously-read data.
	BLOB_READ_MOREDATA,
	BLOB_READ_NBLOCK,
	BLOB_READ_SYSERR,
} blob_read_res;

typedef struct pollinbuf {
	// FIXME this ought move into crlfdata, and we'll just bounce the buffer
	// between the crlf_reader and the chunkdata->dumpoff. Needs libdank
	// API changes to the crlf_reader object.
	crlf_reader cr;
	enum {
		POLLINBUF_MODE_CRLF,
		POLLINBUF_MODE_CHUNK,
		POLLINBUF_MODE_FINACCEPT,
		POLLINBUF_MODE_COUNT
	} mode;
	union {
		struct {
			crlfbuffer_cb cb;
		} crlfdata;
		struct {
			oqueue_key *okey;
			size_t dumpoff;
			chunkdumper_cb cb;
			size_t chunklen,chunkread;
		} chunkdata;
		int findata;
	} modestate;
} pollinbuf;

static blob_read_res
read_blob(int sd,crlf_reader *br,oqueue_key *okey,size_t *bufoff,uint32_t *remains){
	size_t tosend,toread;
	ssize_t readnow;

	if(*remains == 0){
		bitch("Asked to read 0 bytes\n");
		return BLOB_READ_SYSERR;
	}
	// nag("Want %ju at %p:%zu from %d\n",(uintmax_t)*remains,buf,*bufoff,sd);
	// See if we can handle the request with what was left over
	if(br->count){
		tosend = br->count;
		if(tosend > *remains){
			tosend = *remains;
		}
		if(okey){
			memcpy(oqueue_ptrto(okey,*bufoff),br->buf,tosend);
		}
		*bufoff += tosend;
		if( (br->count -= tosend) ){
			memmove(br->buf,br->buf + tosend,br->count);
		}
		if((*remains -= tosend) == 0){
			return (br->count || br->eof || br->readreq) ?
				BLOB_READ_MOREDATA : BLOB_READ_SUCCESS;
		}
	}
	// We need more data. If we previously saw eof, we can't get it...
	if(br->eof){
		return BLOB_READ_SYSERR;
	}
	br->readreq = 0;
	while(br->total < *remains){
		// loop on a possible EINTR
		while((readnow = read(sd,br->buf,br->total)) < 0){
			if(errno == EAGAIN || errno == EWOULDBLOCK){
				return BLOB_READ_NBLOCK;
			}else if(errno != EINTR){
				moan("Error reading %zu from %d\n",br->total,sd);
				return BLOB_READ_SYSERR;
			}
		}
		if(readnow == 0){
			bitch("Got EOF, still wanted %u\n",*remains);
			return BLOB_READ_SYSERR;
		}
		tosend = readnow;
		if(okey){
			memcpy(oqueue_ptrto(okey,*bufoff),br->buf,readnow);
		}
		*bufoff += readnow;
		*remains -= readnow;
	}
	toread = *remains;
	// loop on a possible EINTR
	while((readnow = read(sd,br->buf,toread)) < 0){
		if(errno == EAGAIN || errno == EWOULDBLOCK){
			return BLOB_READ_NBLOCK;
		}else if(errno != EINTR){
			moan("Error reading %zu from %d\n",toread,sd);
			return BLOB_READ_SYSERR;
		}
	}
	if(readnow == 0){
		bitch("Got EOF, still wanted %zu\n",toread);
		return BLOB_READ_SYSERR;
	}
	tosend = readnow;
	if(okey){
		memcpy(oqueue_ptrto(okey,*bufoff),br->buf,tosend);
	}
	*bufoff += tosend;
	if((*remains -= readnow) == 0){
		br->readreq = 1;
		return BLOB_READ_MOREDATA;
	}
	return BLOB_READ_NBLOCK;
}

pollinbuf *create_pollinbuf(void){
	pollinbuf *ret;

	if( (ret = Malloc("pollinbuf",sizeof(*ret))) ){
		memset(ret,0,sizeof(*ret));
		if(init_crlf_reader(&ret->cr) == 0){
			ret->mode = POLLINBUF_MODE_CRLF;
			return ret;
		}
		Free(ret);
	}
	return NULL;
}

static int
pollinbuf_crlf_cb(struct pollfd_state *pfd){
	pollinbuf *pibuf = get_pfd_icap(pfd)->pibuf;
	typeof(pibuf->modestate.crlfdata) *cr;
	crlf_read_res res;
	char *line;

	cr = &pibuf->modestate.crlfdata;
	res = read_crlf_line(&pibuf->cr,pfd->pfd.fd);
	// Since a FIN can arrive on the immediate heels of the request, RX
	// must be disabled between the end of a message and the reply's full
	// transmission (if the reply is completed before the request is
	// received, for instance on an early 204, we skip these steps).
	if(res == CRLF_READ_EOF){
		nag("Got EOF on %d\n",pfd->pfd.fd);
		return -1;
	}
	if(res == CRLF_READ_NBLOCK){
		return 0;
	}
	if(res != CRLF_READ_SUCCESS && res != CRLF_READ_MOREDATA){
		nag("Couldn't read CRLF-terminated line\n");
		return -1;
	}
	line = pibuf->cr.iv.iov_base;
	pibuf->cr.iv.iov_base = NULL;
	if(cr->cb(pfd,line)){
		Free(line);
		return -1;
	}
	Free(line);
	// For edge-triggered RX, we want to return 1 until a read() actually
	// returns -1 + EAGAIN. For level-triggered, return 0 on
	// CRLF_READ_SUCCESS. We're either that or CRLF_READ_MOREDATA.
	return 1;
}

static int
pollinbuf_blob_cb(struct pollfd_state *pfd){
	pollinbuf *pibuf = get_pfd_icap(pfd)->pibuf;
	typeof(pibuf->modestate.chunkdata) *chunk;
	blob_read_res res;
	uint32_t remains;

	chunk = &pibuf->modestate.chunkdata;
	remains = chunk->chunklen - chunk->chunkread;
	res = read_blob(pfd->pfd.fd,&pibuf->cr,chunk->okey,&chunk->dumpoff,&remains);
	if(res == BLOB_READ_SYSERR){
		bitch("Error while reading %ub for chunk\n",remains);
		return -1;
	}
	chunk->chunkread += chunk->chunklen - chunk->chunkread - remains;
	if(res == BLOB_READ_NBLOCK){
		return 0;
	}
	if(chunk->cb(pfd)){
		return -1;
	}
	// For edge-triggered RX, we want to return 1 until a read() actually
	// returns -1 + EAGAIN. For level-triggered, return 0 on
	// BLOB_READ_SUCCESS. We're either that or BLOB_READ_MOREDATA.
	return 1;
}

static int
pollinbuf_fin_accept(struct pollfd_state *pfd){
	pollinbuf *pibuf = get_pfd_icap(pfd)->pibuf;
	char nullbuf[1];
	ssize_t ret;

	if(pibuf->modestate.findata){
		nag("already set findata %d on %d\n",pibuf->modestate.findata,pfd->pfd.fd);
		return 0;
	}
	if((ret = read(pfd->pfd.fd,nullbuf,sizeof(nullbuf))) > 0){
		bitch("data on %d before reply completed\n",pfd->pfd.fd);
		inc_pipeline_violations();
		return -1;
	}else if(ret == 0){
		nag("FIN on %d before reply completed\n",pfd->pfd.fd);
		pibuf->modestate.findata = 1;
	}
	return 0;
}

int pollinbuf_cb(struct poller *p __attribute__ ((unused)),struct pollfd_state *pfd){
	icap_state *is = get_pfd_icap(pfd);
	int ret = -1;

	do{
		switch(is->pibuf->mode){
			case POLLINBUF_MODE_CRLF:
				ret = pollinbuf_crlf_cb(pfd);
				break;
			case POLLINBUF_MODE_CHUNK:
				ret = pollinbuf_blob_cb(pfd);
				break;
			case POLLINBUF_MODE_FINACCEPT:
				ret = pollinbuf_fin_accept(pfd);
				break;
			case POLLINBUF_MODE_COUNT: default:
				bitch("Invalid pollbuf mode %d\n",is->pibuf->mode);
				ret = -1;
				break;
		}
		if(ret <= 0){
			return ret;
		}
	}while(pfd->rxfxn == pollinbuf_cb);
	return 0;
}

int use_finaccept_mode(pollinbuf *pibuf){
	switch(pibuf->mode){
		case POLLINBUF_MODE_CRLF:{
			if(pibuf->cr.count){
				bitch("crlfreader had unhandled data\n");
				return -1;
			}
			pibuf->modestate.findata = pibuf->cr.eof;
			break;
		}case POLLINBUF_MODE_CHUNK:{
			typeof(pibuf->modestate.chunkdata) *chunkdata = &pibuf->modestate.chunkdata;

			if(chunkdata->chunkread){
				bitch("chunkreader had unhandled data\n");
				return -1;
			}
			pibuf->modestate.findata = 0;
			break;
		}case POLLINBUF_MODE_FINACCEPT:{
			nag("already in finaccept state\n"); // shouldn't happen
			return -1;
		}case POLLINBUF_MODE_COUNT: default:{
			bitch("Invalid pollbuf mode %d\n",pibuf->mode);
			return -1;
		}
	}
	pibuf->mode = POLLINBUF_MODE_FINACCEPT;
	return 0;
}

int use_crlf_mode(pollinbuf *pibuf,crlfbuffer_cb cb){
	typeof(pibuf->modestate.crlfdata) *crlfdata = &pibuf->modestate.crlfdata;

	if(pibuf->mode == POLLINBUF_MODE_FINACCEPT){
		if(pibuf->modestate.findata){
			bitch("already got FIN looking for crlfline\n");
			return -1;
		}
	}
	pibuf->mode = POLLINBUF_MODE_CRLF;
	memset(crlfdata,0,sizeof(*crlfdata));
	crlfdata->cb = cb;
	return 0;
}

// Call back once we've copied /chunklen/ bytes into the buffer at /buf/.
void use_chunkdumper_mode(pollinbuf *pibuf,oqueue_key *okey,chunkdumper_cb cb,size_t chunklen){
	typeof(pibuf->modestate.chunkdata) *chunkdata = &pibuf->modestate.chunkdata;

	if(pibuf->mode == POLLINBUF_MODE_CRLF){
		typeof(pibuf->cr) *cr = &pibuf->cr;

		if(cr->base){
			memmove(cr->buf,cr->buf + cr->base,cr->count);
			cr->base = 0;
		}
		cr->examined = 0;
	}
	pibuf->mode = POLLINBUF_MODE_CHUNK;
	memset(chunkdata,0,sizeof(*chunkdata));
	chunkdata->chunklen = chunklen;
	if( (chunkdata->okey = okey) ){
		chunkdata->dumpoff = oqueue_usedlen(okey);
	}
	chunkdata->cb = cb;
}

int drain_pollinbuf(pollinbuf *pibuf,crlfbuffer_cb crlfer,chunkdumper_cb chunker){
	switch(pibuf->mode){
	case POLLINBUF_MODE_CHUNK:{
		typeof(pibuf->modestate.chunkdata) *chunkdata = &pibuf->modestate.chunkdata;

		chunkdata->cb = chunker;
		return 0;
	}case POLLINBUF_MODE_CRLF:{
		typeof(pibuf->modestate.crlfdata) *crlfdata = &pibuf->modestate.crlfdata;

		crlfdata->cb = crlfer;
		return 0;
	}case POLLINBUF_MODE_FINACCEPT:{
		nag("Drain on FIN accept state\n"); // legal, but unexpected
		return 0;
	}case POLLINBUF_MODE_COUNT:{
		break;
	} }
	bitch("Invalid mode %d\n",pibuf->mode);
	return -1;
}

void free_pollinbuf(pollinbuf **pibuf){
	if(pibuf && *pibuf){
		reset_crlf_reader(&(*pibuf)->cr);
		Free(*pibuf);
		*pibuf = NULL;
	}
}
