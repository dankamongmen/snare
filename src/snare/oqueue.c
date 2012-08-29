#include <zlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <snare/oqueue.h>
#include <snare/server.h>
#include <snare/threads.h>
#include <snare/pollinbuf.h>
#include <snare/icap/stats.h>
#include <libdank/utils/fds.h>
#include <libdank/utils/shm.h>
#include <snare/icap/request.h>
#include <libdank/utils/time.h>
#include <libdank/utils/text.h>
#include <snare/icap/response.h>
#include <libdank/utils/string.h>
#include <libdank/utils/maxfds.h>
#include <libdank/utils/syswrap.h>
#include <libdank/utils/threads.h>
#include <libdank/ersatz/compat.h>
#include <libdank/utils/memlimit.h>
#include <snare/icap/encapsulates.h>
#include <libdank/objects/objustring.h>
#include <libdank/modules/ctlserver/ctlserver.h>

// FIXME we ought do something more intelligent than this (hugetlbfs pagesize?)
#define OQUEUE_MULTIPLE (1024u*1024u*2u)

static oqueue_key *oqueue_stack;
static char oqueue_path[PATH_MAX];
static oqueue_infxn oqueue_internal_handler;

// Adjust the parameter against the (unmapped) first mapoff bytes
static inline size_t
virt_len(const oqueue_key *okey,size_t len){
	return len - okey->sw.mw.mapoff;
}

static inline size_t
virt_totallen(const oqueue_key *okey){
	return scratchfile_window_totallen(&okey->sw);
}

static inline size_t
virt_usedlen(const oqueue_key *okey){
	return virt_len(okey,okey->usedlen);
}

// newlen must be the result of an appropriate round_request() operation, and
// considered virtual
static inline int
oqueue_mremap(oqueue_key *okey,size_t newlen){
	return extend_scratchfile_window(&okey->sw,PROT_READ|PROT_WRITE,
					newlen - virt_totallen(okey));
}

static inline size_t
round_request(size_t req){
	int psize = OQUEUE_MULTIPLE;

	return (req / psize + (!!(req % psize))) * psize;
}

static void
ref_icap_encapsulate(oqueue_key *okey){
	++okey->refcount;
}

// refcount ought be 0. we're getting rid of it, unconditionally.
static int
deepfree_icap_encapsulate(oqueue_key *key){
	int ret = 0;

	if(key->refcount){
		bitch("refcount of %d\n",key->refcount);
		ret = -1;
	}
	if(key->sw.fd >= 0){
		ret |= unlink_shmfile(key->fname);
		ret |= Close(key->sw.fd);
	}
	ret |= release_scratchfile_window(&key->sw);
	Free(key->fname);
	Free(key);
	return ret;
}

static int
check_for_dir(scandir_arg d){
	if(strcmp(d->d_name,".") == 0){
		return 0;
	}
	if(strcmp(d->d_name,"..") == 0){
		return 0;
	}
	return 1;
}

static int
clean_directory(const char *dfn){
	struct dirent **namelist;
	int num,printto,ret = 0;
	char ffn[PATH_MAX];

	if(strcmp(dfn,"/") == 0){
		// Linux wants a path with a leading foreslash and no
		// embedded foreshlashes...hack away! don't kill / =].
		bitch("WARNING: CLEANING OUT /dev/shm\n");
		return clean_directory("/dev/shm"); // FIXME horrible
	}
	if((printto = snprintf(ffn,sizeof(ffn),"%s/",dfn)) >= (ssize_t)sizeof(ffn)){
		fprintf(stderr,"Couldn't remove files from %s\n",dfn);
		return -1;
	}
	if((num = scandir(dfn,&namelist,check_for_dir,alphasort)) < 0){
		fprintf(stderr,"Couldn't remove files from %s: %s\n",
				dfn,strerror(errno));
		return -1;
	}
	while(num--){
		snprintf(ffn + printto,sizeof(ffn) - printto,"%s",namelist[num]->d_name);
		ret |= Unlink(ffn);
		// allocated by scandir(3); don't use Free()
		free(namelist[num]);
	}
	free(namelist);
	return ret;
}

static int
create_directory(const char *dfn){
	DIR *dir;

	if((dir = opendir(dfn)) == NULL){
	       	if(errno == ENOENT){
			nag("Creating oqueue at %s\n",dfn);
			if(Mkdir(dfn,0755) || ((dir = Opendir(dfn)) == NULL)){
				return -1;
			}
		}else{
			moan("Couldn't open %s\n",dfn);
			return -1;
		}
	}
	if(Closedir(dir)){
		return -1;
	}
	return 0;
}

// Should only be called within a pollerthread callback context, or a thread
// which has locked against the i/o thread via block_poller(). The original
// callback must have returned VERDICT_COUNT. offset is the offset through
// which the verdict applies, if VERDICT_TRICKLING is supplied (since the
// offset might have advanced since the callback was started; this isn't
// possible in a synchronous callback).
int oqueue_passverdict_internal(struct oqueue_key **key,verdict ver){
	typeof(*(*key)->cbarg) *cbarg;
	int ret;

	cbarg = (*key)->cbarg;
	time_oqueue_session(&(*key)->queuetime);
	ret = free_icap_encapsulate(key);
	if(ver == VERDICT_COUNT){
		inc_stateexceptions(); // return failure
		ret = -1;
	}else if(cbarg == NULL){
		nag("cbarg expired, %s verdict dropped\n",name_verdict(ver));
		inc_verdicts_postconn();
	}else if(ver != VERDICT_SKIP){
		ret |= icap_callback(cbarg,ver,1);
	}
	return ret;
}

int init_oqueue(const char *path,oqueue_infxn cin){
	size_t len;

	if(path == NULL || (len = strlen(path)) == 0){
		nag("no oqueue path; using MAP_ANONYMOUS-backed mmap(2)\n");
		strcpy(oqueue_path,"");
	}else{
		unsigned addslash;

		addslash = (path[len - 1] != '/');
	       	if(strlen(path) + addslash >= sizeof(oqueue_path)){
			bitch("Pathname too long: %s\n",path);
			return -1;
		}else if(create_directory(path)){
			return -1;
		}else if(clean_directory(path)){
			return -1;
		}else{
			strcpy(oqueue_path,path);
			if(addslash){
				oqueue_path[len] = '/';
				oqueue_path[len + 1] = '\0';
			}
			nag("Using shmprefix %s\n",path);
		}
	}
	oqueue_internal_handler = cin;
	return 0;
}

int kill_oqueue(void){
	oqueue_key *o;
	int ret = 0;

	while( (o = oqueue_stack) ){
		oqueue_stack = o->next;
		o->refcount = 0;
		ret |= deepfree_icap_encapsulate(o);
	}
	if(strlen(oqueue_path)){
		ret |= clean_directory(oqueue_path);
	}
	strcpy(oqueue_path,"");
	return ret;
}

// If there's an error, it'll be written out as a consequence; callers
// shouldn't be calling send_icapexception(). txcorresp is the corresponding TX
// length in the (possibly-transcoded) txkey; see last_tx_point. It should only
// be non-zero (and must be non-zero) when status has the value
// ICAP_CALLBACK_INCOMPLETE_BODY.
int queue_icap_encapsulate(oqueue_key *key,struct pollfd_state *pfd,
		icap_callback_e status,size_t txcorresp){
	verdict v = VERDICT_DONE;
	icap_state *icap;

	if(key == NULL || pfd == NULL || (icap = get_pfd_icap(pfd)) == NULL){
		bitch("Won't enqueue bad args (%p %p)\n",key,pfd);
		return -1;
	}
	key->cbarg = pfd;
	ref_icap_encapsulate(key);
	// We might be queued multiple times (in the case of a VERDICT_COUNT
	// with data still incoming, or VERDICT_SKIP) -- count the complete
	// time we're exposed to the oqueue, not just one call's timings.
	if(key->queuetime.tv_sec == 0 && key->queuetime.tv_usec == 0){
		Gettimeofday(&key->queuetime,NULL);
	}
	if(status == ICAP_CALLBACK_INCOMPLETE_BODY){
		if((key->allows_tx_through = txcorresp) == 0){
			bitch("zero txcorresp for incomplete body\n");
			inc_stateexceptions();
			return -1;
		}
	}else if(txcorresp){
		bitch("%zu txcorresp for bad callback type %d\n",txcorresp,status);
		inc_stateexceptions();
		return -1;
	}
	if(oqueue_internal_handler){
		if((v = oqueue_internal_handler(key,icap,status)) == VERDICT_COUNT){
			return 0;
		}else if(v == VERDICT_SKIP){
			time_oqueue_session(&key->queuetime);
			return free_icap_encapsulate(&key);
		}
	}
	time_oqueue_session(&key->queuetime);
	return icap_callback(pfd,v,0) | free_icap_encapsulate(&key);
}

// path must be non-NULL, but it can be the empty string; this latter signifies
// that shared memory / filesystem solutions should not be used, but instead
// anonymous mmaps. if path is not empty, it probably ought be terminated by a
// foreslash (this is not enforced). prefix must not end in a foreslash (this
// is not enforced, but probably ought be).
static inline oqueue_key *
create_oqueue_key(const char * restrict prefix,const char * restrict path){
	oqueue_key *ret;

	if( (ret = Malloc("oqueue key",sizeof(*ret))) ){
		memset(ret,0,sizeof(*ret));
		if( (ret->fname = Malloc("tmpfile name",PATH_MAX)) ){
			ref_icap_encapsulate(ret);
			if(strlen(path) == 0){
				ret->sw.fd = -1;
#define ANON_SUFFIX "-anonymous"
				if(strlen(ANON_SUFFIX) + strlen(prefix) < PATH_MAX){
					strcpy(ret->fname,prefix);
					strcat(ret->fname,ANON_SUFFIX);
#undef ANON_SUFFIX
					return ret;
				}else{
					bitch("prefix too long: %s\n",prefix);
				}
			}else{
				static uintmax_t counter;

				// FIXME This allows a local user to DoS us if
				// they can write to our shm namespace (always
				// true using Linux's default /dev/shm, depends
				// on file permissions in FreeBSD).
				if(snprintf(ret->fname,PATH_MAX,"%s%s-%ju",path,prefix,counter++) < PATH_MAX){
					if((ret->sw.fd = create_shmfile(ret->fname,O_RDWR|O_CREAT|O_EXCL,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) >= 0){
						if(set_fd_close_on_exec(ret->sw.fd) == 0){
							return ret;
						}
						unlink_shmfile(ret->fname);
						Close(ret->sw.fd);
					}
				}else{
					bitch("Name too long: %s%s-%ju\n",path,prefix,counter);
				}
			}
			Free(ret->fname);
		}
		Free(ret);
	}
	return NULL;
}

oqueue_key *create_icap_encapsulate(const char *prefix){
	oqueue_key *ret;

	if( (ret = oqueue_stack) ){
		inc_oqueue_stack(-1);
		inc_oqueue_recycled();
		oqueue_stack = ret->next;
		ret->usedlen = 0;
		ret->refcount = 1;
		ret->allows_tx_through = 0;
		ret->queuetime.tv_sec = 0;
		ret->queuetime.tv_usec = 0;
		ret->cbarg = NULL;
	}else if( (ret = create_oqueue_key(prefix ? prefix : "snare",oqueue_path)) ){
		if(initialize_scratchfile_window(&ret->sw,ret->sw.fd,
				PROT_READ|PROT_WRITE,OQUEUE_MULTIPLE)){
			ret->refcount = 0;
			deepfree_icap_encapsulate(ret);
			ret = NULL;
		}else{
			inc_oqueue_created();
		}
	}
	return ret;
}

// Several things can happen:
//  1) oqueue_key is created, and never associated with oqueue_file
//      - not on oqueue_files; remove now.
//  2) oqueue_key is created, associated, and handoff fails (trackable)
//      - queue_icap_encapsulate() disassociates; remove now.
//  3) oqueue_key is done before obola verdict (error, no rewrite mode race)
//      - kill 
//  4) oqueue_key is done after obola verdict (no rewrite mode race, rewrite)
// This follows from our inability to track the ibola binary. If we could, we
//  could delete the file immediately after it returned, knowing it had been
//  read and inserted into the database. This requires one of:
//   restructuring the poll loop to handle child results + signals, or
//   internalizing ibola via spawning a thread
//  Talking to the database ourselves is orthogonal to the issue.
// Any callback prior to verdict, ie an "ack", resolves nothing.
// A timeout could improve on our chances in the race, but is still racy.
//
// Maybe we want to preserve the file until given a verdict, no matter what,
// but we still have a memory leak on oqueue_file even if diskspace isn't an
// issue somehow (hah!), or else we return an at-best racy code to obola.
int free_icap_encapsulate(oqueue_key **key){
	int ret = 0;

	if(*key){
		// nag("refcount %d becomes %d\n",(*key)->refcount,(*key)->refcount - 1);
		if(--(*key)->refcount == 0){
			if((*key)->sw.mw.maplen > OQUEUE_MULTIPLE){
				deepfree_icap_encapsulate(*key);
			}else if(reset_scratchfile_window(&(*key)->sw,PROT_READ|PROT_WRITE)){
				deepfree_icap_encapsulate(*key);
				ret = -1;
			}else{
				(*key)->next = oqueue_stack;
				oqueue_stack = *key;
				inc_oqueue_stack(1);
			}
		}else if((*key)->refcount < 0){
			bitch("refcount went negative (%d)\n",(*key)->refcount);
			ret = -1;
		}
		*key = NULL;
	}
	if(ret){
		inc_stateexceptions();
	}
	return ret;
}

int orphan_icap_encapsulate(oqueue_key **key){
	int ret = 0;

	if(*key){
		if((*key)->cbarg){
			icap_state *is;

			is = get_pfd_icap((*key)->cbarg);
			if(is == NULL){
				bitch("%u refcount but expired cbarg\n",(*key)->refcount);
				inc_stateexceptions();
				ret = -1;
			}
			(*key)->cbarg = NULL;
		}
		ret |= free_icap_encapsulate(key);
	}
	return ret;
}

// Additive, as opposed to rewriten_icap_encapsulate()
int writen_icap_encapsulate(oqueue_key *okey,const void *buf,size_t s){
	if(virt_totallen(okey) - okey->usedlen < s){
		size_t rr = round_request(virt_totallen(okey) + s);

		if(oqueue_mremap(okey,rr)){
			return -1;
		}
	}
	memcpy(oqueue_ptrto(okey,oqueue_usedlen(okey)),buf,s);
	okey->usedlen += s;
	return 0;
}

// Substitutive, as opposed to writen_icap_encapsulate()
int rewriten_icap_encapsulate(oqueue_key *okey,const void *buf,size_t s){
	if(virt_totallen(okey) < s){
		size_t rr = round_request(s);

		if(oqueue_mremap(okey,rr)){
			return -1;
		}
	}
	memcpy(oqueue_ptrto(okey,0),buf,s);
	okey->usedlen = s;
	return 0;
}

static int
vprintf_icap_encapsulate(oqueue_key *okey,const char *fmt,va_list va){
	unsigned ur;
	va_list tv;
	int r;

	va_copy(tv,va);
	if((r = vsnprintf(oqueue_ptrto(okey,oqueue_usedlen(okey)),0,fmt,tv)) < 0){
		return -1;
	}
	va_end(tv);
	ur = r;
	if(virt_totallen(okey) - okey->usedlen < ur + 1){
		size_t rr = round_request(virt_totallen(okey) + ur + 1);

		if(oqueue_mremap(okey,rr)){
			return -1;
		}
	}
	if(vsnprintf(oqueue_ptrto(okey,oqueue_usedlen(okey)),ur + 1,fmt,va) != r){
		bitch("Internal error during print\n");
		return -1;
	}
	// We don't want to consider the trailing '\0' part of us, so don't add
	// 1 to the buflen we actually store.
	okey->usedlen += ur;
	// nag("buflen: %zu r: %d total: %zu\n",okey->buflen,r,okey->buflen + r);
	return r;
}

int printf_icap_encapsulate(oqueue_key *okey,const char *fmt,...){
	va_list ap;
	int r;

	va_start(ap,fmt);
	r = vprintf_icap_encapsulate(okey,fmt,ap);
	va_end(ap);
	return r;
}

/* from zlib.h (debian zlib1g-dev 1:1.2.3.3.dfsg-12)

    deflate compresses as much data as possible, and stops when the input
  buffer becomes empty or the output buffer becomes full. It may introduce some
  output latency (reading input without producing any output) except when
  forced to flush.

    The detailed semantics are as follows. deflate performs one or both of the
  following actions:

  - Compress more input starting at next_in and update next_in and avail_in
    accordingly. If not all input can be processed (because there is not
    enough room in the output buffer), next_in and avail_in are updated and
    processing will resume at this point for the next call of deflate().

  - Provide more output starting at next_out and update next_out and avail_out
    accordingly. This action is forced if the parameter flush is non zero.
    Forcing flush frequently degrades the compression ratio, so this parameter
    should be set only when necessary (in interactive applications).
    Some output may be provided even if flush is not set.

  Before the call of deflate(), the application should ensure that at least
  one of the actions is possible, by providing more input and/or consuming
  more output, and updating avail_in or avail_out accordingly; avail_out
  should never be zero before the call. The application can consume the
  compressed output when it wants, for example when the output buffer is full
  (avail_out == 0), or after each call of deflate(). If deflate returns Z_OK
  and with zero avail_out, it must be called again after making room in the
  output buffer because there might be more output pending.

    Normally the parameter flush is set to Z_NO_FLUSH, which allows deflate to
  decide how much data to accumualte before producing output, in order to
  maximize compression.

    If the parameter flush is set to Z_SYNC_FLUSH, all pending output is
  flushed to the output buffer and the output is aligned on a byte boundary, so
  that the decompressor can get all input data available so far. (In particular
  avail_in is zero after the call if enough output space has been provided
  before the call.)  Flushing may degrade compression for some compression
  algorithms and so it should be used only when necessary.

    If flush is set to Z_FULL_FLUSH, all output is flushed as with
  Z_SYNC_FLUSH, and the compression state is reset so that decompression can
  restart from this point if previous compressed data has been damaged or if
  random access is desired. Using Z_FULL_FLUSH too often can seriously degrade
  compression.

    If deflate returns with avail_out == 0, this function must be called again
  with the same value of the flush parameter and more output space (updated
  avail_out), until the flush is complete (deflate returns with non-zero
  avail_out). In the case of a Z_FULL_FLUSH or Z_SYNC_FLUSH, make sure that
  avail_out is greater than six to avoid repeated flush markers due to
  avail_out == 0 on return.

    If the parameter flush is set to Z_FINISH, pending input is processed,
  pending output is flushed and deflate returns with Z_STREAM_END if there
  was enough output space; if deflate returns with Z_OK, this function must be
  called again with Z_FINISH and more output space (updated avail_out) but no
  more input data, until it returns with Z_STREAM_END or an error. After
  deflate has returned Z_STREAM_END, the only possible operations on the
  stream are deflateReset or deflateEnd.

    Z_FINISH can be used immediately after deflateInit if all the compression
  is to be done in a single step. In this case, avail_out must be at least
  the value returned by deflateBound (see below). If deflate does not return
  Z_STREAM_END, then it must be called again as described above.
    deflate() sets strm->adler to the adler32 checksum of all input read
  so far (that is, total_in bytes).

    deflate() may update strm->data_type if it can make a good guess about
  the input data type (Z_BINARY or Z_TEXT). In doubt, the data is considered
  binary. This field is only for information purposes and does not affect
  the compression algorithm in any manner.

    deflate() returns Z_OK if some progress has been made (more input
  processed or more output produced), Z_STREAM_END if all input has been
  consumed and all output has been produced (only when flush is set to
  Z_FINISH), Z_STREAM_ERROR if the stream state was inconsistent (for example
  if next_in or next_out was NULL), Z_BUF_ERROR if no progress is possible
  (for example avail_in or avail_out was zero). Note that Z_BUF_ERROR is not
  fatal, and deflate() can be called again with more input and more output
  space to continue compressing. */
int deflate_icap_encapsulate(oqueue_key *okey,z_stream *z,size_t *news){
	int ret,flag;
	uLong bound;

	*news = 0;
	if(z->avail_in == 0){
		flag = Z_FINISH;
	}else{
		flag = Z_NO_FLUSH;
	}
	// usedlen is invalidated across this loop; must use ->usedlen + *news!
	do{
		bound = deflateBound(z,z->avail_in);
		if(virt_totallen(okey) - (okey->usedlen + *news) < bound){
			size_t rr = round_request(okey->usedlen + *news + bound);

			if(oqueue_mremap(okey,rr)){
				return -1;
			}
		}
		z->next_out = (Bytef *)oqueue_ptrto(okey,oqueue_usedlen(okey) + *news);
		z->avail_out = virt_totallen(okey) - (virt_usedlen(okey) + *news);
		*news += z->avail_out;
		// nag("%zu available for deflation of %zu\n",*news,s);
		ret = deflate(z,flag);
		*news -= z->avail_out;
		if(ret != Z_OK){
			if(ret == Z_STREAM_END){
				if(flag != Z_FINISH){
					bitch("Premature end of stream (%u left)\n",z->avail_in);
					return -1;
				}
			}else{
				bitch("Couldn't deflate (%s?)\n",zliberror(ret));
				return -1;
			}
		}
	}while(z->avail_in || (flag == Z_FINISH && ret == Z_OK));
	okey->usedlen += *news;
	// nag("Deflated %zu to %zu\n",s,*news);
	return 0;
}

// Expects z->next_in to have been set up already.
int inflate_icap_encapsulate(oqueue_key *okey,z_stream *z,size_t s,size_t *news){
	// nag("Need to inflate %zu\n",s);
	z->avail_in = s;
	*news = 0;
	// usedlen is invalidated across this loop; must use ->usedlen + *news!
	do{
		size_t rr = round_request(okey->usedlen + *news + s);
		int ret;

		// FIXME what if we're getting Z_BUF_ERROR but totallen == rr?
		if(virt_totallen(okey) < rr){
			if(oqueue_mremap(okey,rr)){
				return -1;
			}
		}
		z->next_out = (Bytef *)oqueue_ptrto(okey,oqueue_usedlen(okey) + *news);
		z->avail_out = virt_totallen(okey) - (virt_usedlen(okey) + *news);
		*news += z->avail_out;
		if((ret = inflate(z,Z_NO_FLUSH)) != Z_OK){
			if(ret == Z_STREAM_END && !z->avail_in){
				nag("Got Z_STREAM_END\n");
			}else if(ret == Z_BUF_ERROR){
				nag("Need more foward progress\n");
			}else{
				bitch("Couldn't inflate (%s?)\n",zliberror(ret));
				return -1;
			}
		}
		*news -= z->avail_out;
	}while(z->avail_in);
	okey->usedlen += *news;
	// nag("Inflated %zu to %zu\n",s,*news);
	return 0;
}

int drainchunk_icap_encapsulate(oqueue_key *okey,struct pollinbuf *pibuf,
					size_t s,chunkdumper_cb cb){
	if(virt_totallen(okey) < s){
		size_t rr = round_request(s);

		if(oqueue_mremap(okey,rr)){
			return -1;
		}
	}
	use_chunkdumper_mode(pibuf,okey,cb,s);
	// ->usedlen is not updated until we actually perform the read (and
	// likely not even then; after all, we're draining the data)!
	return 0;
}

int readchunk_icap_encapsulate(oqueue_key *okey,struct pollinbuf *pibuf,
					size_t s,chunkdumper_cb cb){
	if(virt_totallen(okey) - okey->usedlen < s){
		size_t rr = round_request(virt_totallen(okey) + s);

		if(oqueue_mremap(okey,rr)){
			return -1;
		}
	}
	use_chunkdumper_mode(pibuf,okey,cb,s);
	// ->usedlen is not updated until we actually perform the read!
	return 0;
}

// Release the underlying map up through "through" (a virtual offset).
int window_icap_encapsulate(oqueue_key *okey,size_t through){
	unsigned chunkstofree;

	if(through > oqueue_usedlen(okey)){
		bitch("Invalid release (%zu > %zu)\n",through,oqueue_usedlen(okey));
		return -1;
	}
	chunkstofree = virt_len(okey,through) / OQUEUE_MULTIPLE;
	if(chunkstofree == 0){
		// no point in releasing such a small segment; it'll just waste
		// a system call and invite fragmentation
		return 0;
	}
	nag("Freeing %ub (to %ju)\n",chunkstofree * OQUEUE_MULTIPLE,
		(uintmax_t)okey->sw.mw.mapoff + through / OQUEUE_MULTIPLE * OQUEUE_MULTIPLE);
	if(slide_scratchfile_window(&okey->sw,PROT_READ|PROT_WRITE,chunkstofree * OQUEUE_MULTIPLE)){
		return -1;
	}
	return 0;
}

int stringize_oqueue_key(ustring *u,const char *str,const oqueue_key *okey){
	if(printUString(u,"<%s>",str) < 0){
		return -1;
	}
	if(okey->sw.fd >= 0){
		if(printUString(u,"<fn>%s</fn><fd>%d</fd>",okey->fname,okey->sw.fd) < 0){
			return -1;
		}
	}
	if(printUString(u,"<maplen>%zu</maplen>",scratchfile_window_maplen(&okey->sw)) < 0){
		return -1;
	}
	if(printUString(u,"<offset>%ju</offset>",(uintmax_t)okey->sw.mw.mapoff) < 0){
		return -1;
	}
	if(printUString(u,"<reallen>%zu</reallen>",okey->usedlen) < 0){
		return -1;
	}
	if(printUString(u,"</%s>",str) < 0){
		return -1;
	}
	return 0;
}
