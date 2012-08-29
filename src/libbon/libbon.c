#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <libbon/libbon.h>
#include <libdank/utils/fds.h>
#include <libdank/utils/string.h>
#include <libdank/utils/syswrap.h>
#include <libdank/utils/memlimit.h>
#include <libdank/objects/lexers.h>
#include <libdank/objects/logctx.h>
#include <libdank/objects/objustring.h>
#include <libdank/objects/crlfreader.h>

typedef struct libbonreq {
	const void *buf;
	size_t buflen;
	void *key;
	int result,complete;
	struct libbonreq *next;
	char *description;
	unsigned probability;
	void *opaque;
	char shmkey[PATH_MAX]; // FIXME shrink this down maybe?
} libbonreq;

typedef struct libbon_bridge {
	pid_t pid;
	int rpipe,wpipe;
	crlf_reader crdr;
	char *shmprefix;
	uintmax_t next_shm_key;
	libbonreq *donestack,*pendinglist;
	libbonreq *needtx,**needtxenqueue; // see libbon_analyze()
	// Taken from the Embedder's Guide
	unsigned Version[3],EngineVersion[3];
	char OEMAPIVersion[64],OEMEngineVersion[64];
} libbon_bridge;

// This must only be called if the subprocess is dead or dying, since we don't
// supply WNOHANG (we can't, as otherwise we can't wait on the child without a
// race, and this is to be used synchronously on exceptional events, like a
// failed I/O operation or SIGCHLD on a KV_SIGNAL kqueue or signalfd).
static int
block_on_child_exit(libbon_bridge *lbr){
	int status,ret = 0;

	if(lbr->pid >= 0){
		if(Waitpid(lbr->pid,&status,0) == lbr->pid){
			if(WIFEXITED(status)){
				nag("Got return status of %d\n",WEXITSTATUS(status));
				ret = -1;
			}else if(WIFSIGNALED(status)){
				bitch("Exited on signal %d (%s)\n",WTERMSIG(status),strsignal(WTERMSIG(status)));
				if(WTERMSIG(status) != SIGTERM){
					ret = -1;
				}
			}else{
				nag("Unknown exit status %d\n",status);
			}
		}else{
			// FIXME icap_stats / bug 901
			// ret = -1;
		}
		lbr->pid = -1;
	}
	return ret;
}

// fds is an array with space for 2 ints (file descriptors): the parent and
// child sides of the AF_UNIX socketpair. fds[1] becomes stsio of the new
// process, while the parent uses fds[0].
static int
setup_bonpipes(int *fds){
	if(Socketpair(AF_UNIX,SOCK_STREAM,0,fds)){
		return -1;
	}
	if(set_fd_nonblocking(fds[0])){
		Close(fds[0]);
		Close(fds[1]);
		return -1;
	}
	if(set_fd_close_on_exec(fds[0])){
		Close(fds[0]);
		Close(fds[1]);
		return -1;
	}
	return 0;
}

static int
close_libbon_pipefds(libbon_bridge *lbr){
	int ret = 0;

	if(lbr->rpipe >= 0){
		ret |= Close(lbr->rpipe);
		lbr->rpipe = -1;
	}
	return ret;
}

// fdarray ought be the two integer file descriptors produced by a socketpair()
// call (see setup_bonpipes()); this child will use fdarray[1].
static void
libbon_spawn(const int *fdarray,const char *bontool,const char *sigsdir){
	int i;

	if(close(fdarray[0])){
		fprintf(stderr,"Couldn't close %d (%s?)\n",
			fdarray[0],strerror(errno));
		exit(EXIT_FAILURE);
	}
	if(dup2(fdarray[1],STDIN_FILENO) != STDIN_FILENO || dup2(fdarray[1],STDOUT_FILENO) != STDOUT_FILENO){
		fprintf(stderr,"Couldn't dup2 %d (%s?)\n",
			fdarray[1],strerror(errno));
		exit(EXIT_FAILURE);
	}
	if(close(fdarray[1])){
		printf("Error closing fd %d\n",fdarray[1]);
		exit(EXIT_FAILURE);
	}
	// FIXME hack around FreeBSD's lib32 exec(2) not honoring the
	// close-on-exec flag...
	for(i = STDERR_FILENO + 1 ; i < getdtablesize() ; ++i){
		close(i);
	}
	if(execl(bontool,bontool,sigsdir,NULL)){
		printf("Couldn't run %s %s (%s?)\n",
			bontool,sigsdir,strerror(errno));
	}
}

libbon_bridge *init_libbon_bridge(const char *bontool,const char *sigsdir,
					const char *shmprefix){
	libbon_bridge *ret;
	int fdarray[2];
	pid_t fret;

	if((ret = Malloc("bonbridge",sizeof(*ret))) == NULL){
		return NULL;
	}
	memset(ret,0,sizeof(*ret));
	if(shmprefix){
		if((ret->shmprefix = Strdup(shmprefix)) == NULL){
			Free(ret);
			return NULL;
		}
	}
	if(init_crlf_reader(&ret->crdr)){
		Free(ret->shmprefix);
		Free(ret);
		return NULL;
	}
	nag("Running bontool at %s\n",bontool);
	if(setup_bonpipes(fdarray)){
		reset_crlf_reader(&ret->crdr);
		Free(ret->shmprefix);
		Free(ret);
		return NULL;
	}
	ret->rpipe = fdarray[0];
	ret->wpipe = fdarray[0];
	if((fret = Fork(bontool)) < 0){
		Close(fdarray[1]);
		close_libbon_pipefds(ret);
		free_libbon_bridge(ret);
		return NULL;
	}else if(fret == 0){ // child
		libbon_spawn(fdarray,bontool,sigsdir);
		exit(EXIT_FAILURE);
	}
	ret->pid = fret;
	Close(fdarray[1]);
	ret->needtxenqueue = &ret->needtx;
	return ret;
}

int get_libbon_fd(const libbon_bridge *lbr){
	return lbr->rpipe;
}

int get_libbon_pid(const libbon_bridge *lbr){
	return lbr->pid;
}

void invalidate_libbon_wfd(libbon_bridge *lbr){
	if(lbr->rpipe == lbr->wpipe){
		lbr->rpipe = -1;
	}
	lbr->wpipe = -1;
}

static int
kill_libbon_bridge(libbon_bridge *lbr){
	if(lbr->pid < 0){
		nag("libbon subprocess already shut down\n");
		return -1;
	}
	// This might error out, for instance, if the child dies while we're
	// shutting down and we haven't seen the change (so as to affect pid).
	// If pid >= 0, we've created the process, and not yet wait()ed on it.
	// That is all we can know.
	Kill(lbr->pid,SIGTERM);
	return 0;
}

int stop_libbon_bridge(libbon_bridge *lbr){
	int ret = 0;

	if(lbr){
		ret |= close_libbon_pipefds(lbr);
		ret |= kill_libbon_bridge(lbr);
		ret |= block_on_child_exit(lbr);
		free_libbon_bridge(lbr);
	}
	return ret;
}

// To be called upon receipt of SIGCHLD for the child pid
int sigchld_libbon_bridge(libbon_bridge *lbr){
	if(lbr->pid < 0){
		nag("libbon subprocess already shut down\n");
		return -1;
	}
	nag("Receipt SIGCHLD for PID %jd\n",(intmax_t)lbr->pid);
	lbr->pid = -1;
	return 0;
}

// POSIX.1-2001 says that write(2)s of less than PIPE_BUF bytes must be atomic.
// Thus, in non-blocking mode, we will never get a partial write (so long as we
// never try to write more than PIPE_BUF) -- only success, EAGAIN, or true
// error/SIGPIPE. This means we needn't keep an actual output buffer, but
// merely a stack of scans pending on availability of request transmission.
static int
attempt_libbon_tx(libbon_bridge *lbr,libbonreq *lr){
	char lenbuf[80]; // FIXME arrrrgh
	struct iovec iovec[] = { // FIXME can't be const when spr's computed :/
		// FIXME with the partial flag set, we get false negatives
		// { .iov_base = lr->complete ? "s" : "p", .iov_len = 1,	},
		{ .iov_base = "s", .iov_len = 1,	},
		{ .iov_base = lenbuf, },
		{ .iov_base = lr->shmkey, .iov_len = strlen(lr->shmkey),	},
		{ .iov_base = "\xd\xa", .iov_len = 2,	},
	};
	size_t sum = 1 + strlen(lr->shmkey) + 2;
	ssize_t r;
	int spr;

	if((spr = snprintf(lenbuf,sizeof(lenbuf),"%zu,",lr->buflen)) >= (int)sizeof(lenbuf)){ // FIXME argh
		bitch("Couldn't print '%zu,' into %zub\n",lr->buflen,sizeof(lenbuf));
		return -1;
	}
	sum += spr;
	iovec[1].iov_len = spr; // FIXME terrible!
	if(sum > PIPE_BUF){
		bitch("Needed to write %zu, PIPE_BUF = %d\n",sum,PIPE_BUF);
		return -1;
	}
	if((r = Writev(lbr->wpipe,iovec,sizeof(iovec) / sizeof(*iovec))) < 0 || (size_t)r != sum){
		moan("Wanted to write %zu, got %zd\n",sum,r);
		return -1;
	}
	return 0;
}

static void
destroy_libbonreq(libbonreq *lr){
	if(lr){
		Free(lr->description);
		Free(lr);
	}
}

int libbon_analyze(libbon_bridge *lbr,const char *shmkey,const void *buf,
			size_t buflen,int complete,void *opaque){
	libbonreq *lr;

	if(lbr->wpipe < 0){
		bitch("Cannot write to nonexistent pipe\n");
		return -1;
	}
	if(buflen == 0){
		bitch("Will not analyze 0-byte buffers\n");
		return -1;
	}
	if((lr = Malloc("libbonreq",sizeof(*lr))) == NULL){
		return -1;
	}
	strcpy(lr->shmkey,shmkey);
	lr->buflen = buflen;
	lr->buf = buf;
	lr->opaque = opaque;
	lr->result = -1;
	lr->complete = complete;
	if(attempt_libbon_tx(lbr,lr) == 0){
		lr->next = lbr->pendinglist;
		lbr->pendinglist = lr;
	}else if(errno == EAGAIN){
		*lbr->needtxenqueue = lr;
		lbr->needtxenqueue = &lr->next;
	}else{
		destroy_libbonreq(lr);
		return -1;
	}
	return 0;
}

static int
handle_status_tripartite(unsigned ver[3],const char *vstr,char term){
	if(lex_u32(&vstr,&ver[0])){
		return -1;
	}
	if(*vstr != '.'){
		return -1;
	}
	++vstr;
	if(lex_u32(&vstr,&ver[1])){
		return -1;
	}
	if(*vstr != '.'){
		return -1;
	}
	++vstr;
	if(lex_u32(&vstr,&ver[2])){
		return -1;
	}
	if(*vstr != term){
		return -1;
	}
	return 0;
}

static int
handle_status_result(libbon_bridge *lbr,const char *vstr){
	const char *ver1,*ver2,*ver3,*ver4;

	nag("Read on %d: %s\n",lbr->rpipe,vstr);
	if(vstr[0] != '|'){
		bitch("Malformed status message, expected |ver|ver|ver|ver\n");
		return -1;
	}
	ver1 = ++vstr;
	while(isdigit(*vstr) || *vstr == '.'){
		++vstr;
	}
	if(*vstr != '|' || vstr == ver1){
		bitch("Malformed status message, expected |ver|ver|ver|ver\n");
		return -1;
	}
	ver2 = ++vstr;
	while(isdigit(*vstr) || *vstr == '.'){
		++vstr;
	}
	if(*vstr != '|' || vstr == ver2){
		bitch("Malformed status message, expected |ver|ver|ver|ver\n");
		return -1;
	}
	ver3 = ++vstr;
	while(isdigit(*vstr) || *vstr == '.'){
		++vstr;
	}
	if(*vstr != '|' || vstr == ver3){
		bitch("Malformed status message, expected |ver|ver|ver|ver\n");
		return -1;
	}
	ver4 = ++vstr;
	while(isdigit(*vstr) || *vstr == '.'){
		++vstr;
	}
	if(*vstr || vstr == ver4){
		bitch("Malformed status message, expected |ver|ver|ver|ver\n");
		return -1;
	}
	// subtract 1 for the skipped '|', but add 1 back for the \0
	if(ver2 - ver1 > (ptrdiff_t)sizeof(lbr->OEMAPIVersion)){
		bitch("OEMAPIVersion string too long\n");
		return -1;
	}
	if(vstr - ver3 >= (ptrdiff_t)sizeof(lbr->OEMEngineVersion)){
		bitch("OEMAPIVersion string too long\n");
		return -1;
	}
	if(handle_status_tripartite(lbr->Version,ver2,'|')){
		fprintf(stderr,"Format error (expected |ver.ver.ver|, got %s\n",ver2);
		return -1;
	}
	if(handle_status_tripartite(lbr->EngineVersion,ver4,'\0')){
		fprintf(stderr,"Format error (expected |ver.ver.ver, got %s\n",ver4);
		return -1;
	}
	// we're destructive here on failure in media res FIXME
	// FIXME extract from ver4
	memcpy(lbr->OEMAPIVersion,ver1,ver2 - ver1 - 1);
	lbr->OEMAPIVersion[ver2 - ver1 - 1] = '\0';
	memcpy(lbr->OEMEngineVersion,ver3,ver4 - ver3 - 1);
	lbr->OEMEngineVersion[ver4 - ver3 - 1] = '\0';
	nag("Valid status message, %s %s\n",lbr->OEMAPIVersion,lbr->OEMEngineVersion);
	return 0;
}

static int
handle_result(libbon_bridge *lbr,const char *rstr){
	const char *key,*name,*nameend,*probability,*lenstr;
	libbonreq *cur,**prev;
	uint64_t len;
	uint8_t prob;
	int result;

	switch(rstr[0]){
		case 'i': result = 1; break;
		case 'c': result = 0; break;
		case 'e': result = -1; break;
		case 's': return handle_status_result(lbr,rstr + 1); break;
		case '#': nag("libbon-diag: %s\n",rstr + 1); return 0; break;
		default: bitch("Unknown control code %c (%x)\n",rstr[0],rstr[0]);
			return -1;
	}
	if(rstr[1] != '|'){
		bitch("Format error (expected '|', got %c (0x%x))\n",rstr[1],rstr[1]);
		return -1;
	}
	key = name = rstr + 2;
	while(*key && *key != '|'){
		++key;
	}
	if(*key != '|'){
		bitch("Format error (expected '|description|', got %s)\n",name);
		return -1;
	}
	probability = ++key;
	nameend = key - 1;
	while(*key && *key != '|'){
		++key;
	}
	if(*key != '|'){
		bitch("Format error (expected '|probability|', got %s)\n",probability);
		return -1;
	}
	if(key == probability){
		prob = 100;
	}else if(lex_u8(&probability,&prob)){
		bitch("Format error (expected '|probability|', got %s)\n",probability);
		return -1;
	}
	lenstr = ++key;
	while(*key && *key != '|'){
		++key;
	}
	if(*key != '|' || key == lenstr){
		bitch("Format error (expected '|length|', got %s)\n",lenstr);
		return -1;
	}
	if(lex_u64(&lenstr,&len)){
		bitch("Format error (expected '|length|', got %s)\n",lenstr);
		return -1;
	}
	++key;
	// FIXME accelerate! binary search on keylen or something
	for(prev = &lbr->pendinglist ; (cur = *prev) ; prev = &cur->next){
		if(cur->buflen == len && strcmp(cur->shmkey,key) == 0){
			*prev = cur->next;
			cur->next = lbr->donestack;
			if((cur->description = Strndup(name,nameend - name)) == NULL){
				result = -1;
			}
			lbr->donestack = cur;
			cur->result = result;
			if(!(cur->complete || result)){
				cur->probability = 0;
			}else{
				cur->probability = prob;
			}
			nag("Passed %d result for %s (len %ju), complete: %d\n",cur->result,key,(uintmax_t)len,cur->complete);
			return 0;
		}
	}
	bitch("Unknown key/len [\"%s\"/%ju] for %c (%x)\n",
			key,(uintmax_t)len,rstr[0],rstr[0]);
	return 0;
}

// If we return an error from here, don't close the rpipe; just mark it as -1,
// as it'll be closed by the poller (this doesn't apply to write errors, as
// they're made on behalf (from the poller's view) of an ICAP file descriptor).
int libbon_rx_callback(libbon_bridge *lbr){
	crlf_read_res ret;

	do{
		// nag("Reading on pipe %d\n",lbr->rpipe);
		ret = read_crlf_line(&lbr->crdr,lbr->rpipe);
		switch(ret){
		case CRLF_READ_SYSERR: case CRLF_READ_EOF:
		case CRLF_READ_LONGLINE: case CRLF_READ_SHORTLINE:
			nag("bonware failure rpipe %d (got %d)\n",lbr->rpipe,ret);
		       	return -1; break;
		case CRLF_READ_NBLOCK:
			return 0;
		case CRLF_READ_SUCCESS: case CRLF_READ_MOREDATA:{
			char *nl,*line;

			line = lbr->crdr.iv.iov_base;
			// Error out on too long of an input line -- we don't want to
			// interpret a command in media res.
			if((nl = strrchr(line,'\xd')) == NULL){
				bitch("Line too long: %s\n",line);
				return -1;
			}
			if(nl[1] != '\xa'){
				bitch("Not terminated with CRLF: %s\n",line);
				return -1;
			}
			*nl = '\0';
			if(handle_result(lbr,line)){
				Free(line);
				return -1;
			}
			Free(line);
			break;
		}default:
			bitch("Unknown return code %d on %d\n",ret,lbr->rpipe);
			return -1;
		}
	}while(ret == CRLF_READ_MOREDATA);
	return 0;
}

// lres->name must be at least SCANMAPI_MAX_STRLEN characters.
void *libbon_pop_analysis(libbon_bridge *lbr,libbon_result *lres){
	void *ret = NULL;
	libbonreq *tmp;

	if( (tmp = lbr->donestack) ){
		lbr->donestack = tmp->next;
		lres->length = tmp->buflen;
		lres->result = tmp->result;
		lres->probability = tmp->probability;
		strcpy(lres->name,tmp->description);
		ret = tmp->opaque;
		destroy_libbonreq(tmp);
	}
	return ret;
}

int reconfigure_libbon_bridge(libbon_bridge *lbr){
	ssize_t r;

	#define RECONFIGURATION_CMD "r"CRLF
	if(lbr->wpipe < 0){ // FIXME relaunch?
		bitch("No pipe on which to write reconfiguration request\n");
		return -1;
	}
	// FIXME handle short writes / EAGAIN etc
	if((r = Write(lbr->wpipe,RECONFIGURATION_CMD,__builtin_strlen(RECONFIGURATION_CMD))) < 0){
		return -1;
	}
	if((size_t)r < __builtin_strlen(RECONFIGURATION_CMD)){
		return -1;
	}
	nag("Sent reconfiguration command on %d\n",lbr->wpipe);
	return 0;
	#undef RECONFIGURATION_CMD
}

void free_libbon_bridge(libbon_bridge *lbr){
	if(lbr){
		libbonreq *lr;

		while( (lr = lbr->needtx) ){
			lbr->needtx = lr->next;
			destroy_libbonreq(lr);
		}
		while( (lr = lbr->donestack) ){
			lbr->donestack = lr->next;
			destroy_libbonreq(lr);
		}
		while( (lr = lbr->pendinglist) ){
			lbr->pendinglist = lr->next;
			destroy_libbonreq(lr);
		}
		reset_crlf_reader(&lbr->crdr);
		Free(lbr->shmprefix);
		Free(lbr);
	}
}

int libbon_bonware_version(libbon_bridge *lbr){
	ssize_t r;

	#define STATUS_CMD "s"CRLF
	if(lbr->wpipe < 0){
		bitch("No pipe on which to write status request\n");
		return -1;
	}
	// FIXME handle short writes / EAGAIN etc
	if((r = Write(lbr->wpipe,STATUS_CMD,__builtin_strlen(STATUS_CMD))) < 0){
		return -1;
	}
	if((size_t)r < __builtin_strlen(STATUS_CMD)){
		return -1;
	}
	nag("Sent status command on %d\n",lbr->wpipe);
	return 0;
	#undef STATUS_CMD
}

// If we return an error from here, don't close the wpipe; just mark it as -1,
// as it'll be closed by the poller (this doesn't apply to normal write errors,
// as they're made on behalf (from the poller's view) of an ICAP fd).
int libbon_tx_available(libbon_bridge *lbr){
	libbonreq *lr;

	while( (lr = lbr->needtx) ){
		if(attempt_libbon_tx(lbr,lr) == 0){
			lbr->needtx = lr->next;
			lr->next = lbr->pendinglist;
			lbr->pendinglist = lr;
		}else if(errno == EAGAIN){
			*lbr->needtxenqueue = lr;
			lbr->needtxenqueue = &lr->next;
			return -1;
		}else{
			lbr->wpipe = -1;
			return -1;
		}
	}
	lbr->needtxenqueue = &lbr->needtx;
	return 0;
}

int libbon_stringize_version(ustring *u,libbon_bridge *lbr){
#define AMALWAREVER_TAG "amversion"
	if(printUString(u,"<" AMALWAREVER_TAG ">%s-%s-%u.%u.%u-%u.%u.%u</" AMALWAREVER_TAG ">",
			lbr->OEMAPIVersion,lbr->OEMEngineVersion,
			lbr->Version[0],lbr->Version[1],lbr->Version[2],
			lbr->EngineVersion[0],lbr->EngineVersion[1],lbr->EngineVersion[2]) < 0){
		return -1;
	}
#undef AMALWAREVER_TAG
	return 0;
}

// Both must be char arrays of 64 cells or more
int libbon_get_versions(libbon_bridge *lbr,char *OEMAPIVersion,char *OEMEngineVersion,
			unsigned Version[3],unsigned EngineVersion[3]){
	if(strlen(lbr->OEMAPIVersion) == 0 || strlen(lbr->OEMEngineVersion) == 0){
		bitch("Haven't received a status message yet\n");
		return -1;
	}
	strcpy(OEMAPIVersion,lbr->OEMAPIVersion);
	strcpy(OEMEngineVersion,lbr->OEMEngineVersion);
	memcpy(Version,lbr->Version,sizeof(lbr->Version));
	memcpy(EngineVersion,lbr->EngineVersion,sizeof(lbr->EngineVersion));
	return 0;
}
