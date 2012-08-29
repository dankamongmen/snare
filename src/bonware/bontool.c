#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <bonware/bonware.h>

typedef struct marshal {
	char mtype;
	struct marshal *next;
	size_t mlen;
	char path[PATH_MAX + 1];
} marshal;

static int verbose;
static unsigned outstanding,shuttingdown;
static pthread_cond_t daemoncond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t daemonlock = PTHREAD_MUTEX_INITIALIZER;
static marshal *pending_scans,**enqueue_scans = &pending_scans;

#define CRLF "\xd\xa"
#define BONDAEMON_ERROR		'e'
#define BONDAEMON_MALWARE	'i'
#define BONDAEMON_CLEAN		'c'
#define BONDAEMON_STATUS	's'
#define verprintf(fmt,...) \
	do{ if(verbose){ printf("#"fmt,##__VA_ARGS__); } }while(0)

static void
usage(char **progname,int ret){
	fprintf(stderr,"Usage: %s updatesdir [filestoscan]\n",*progname);
	fprintf(stderr,"You supplied: %s ",*progname);
	while(*++progname){
		fprintf(stderr,"%s ",*progname);
	}
	fprintf(stderr,"\n");
	exit(ret);
}

// On entry, a clean verdict will have ->Probability of 0. Boost it up to 100
// if the prononciation was actually "clean", but leave "need more data" as is.
// All other errors are also converted to a Probability of 100 (from 0).
static int
handle_results(const char *fn,SCANMAPI_RESULT *res,int complete){
	int ret = 0;

	if(res->Flags & SCANMAPI_RESULT_DETECTED){
		fprintf(stderr,"  \\---> Detected malware (%s, %u%%) in %s!\n",
				res->Name,res->Probability,fn);
		ret = 1;
	}
	if(res->Flags & SCANMAPI_RESULT_MODIFIED){
		fprintf(stderr,"  \\---> Modified %s!\n",fn);
		ret = 1;
	}
	if(res->Flags & SCANMAPI_RESULT_BYHEURISTICS){
		fprintf(stderr,"  \\---> Heuristic malware detection (%s, %u%%) in %s!\n",
				res->Name,res->Probability,fn);
		ret = 1;
	}
	if(ret == 0){ // clean, or error
		res->Probability = 100;
	}
	if(res->Flags & SCANMAPI_RESULT_FAILED){
		if(res->ReasonCode != SCANMAPI_ERROR_NEEDMOREDATA || complete){
			fprintf(stderr,"  \\---> Scanning failed for %s (%s)!\n",fn,
					bonware_strerror(res->ReasonCode));
			ret = -1;
		}else{
			res->Probability = 0;
		}
	}
	ret |= bonware_free_result(res);
	return ret;
}

static int
scan_as_buffer(const char *fn){
	int fd = -1,ret = -1;
	SCANMAPI_REQUEST req;
	SCANMAPI_RESULT res;
	void *map = NULL;
	struct stat buf;

	if((fd = open(fn,O_RDONLY)) < 0){
		fprintf(stderr," Couldn't open %s (%s?)\n",fn,strerror(errno));
		goto done;
	}
	if(fstat(fd,&buf)){
		fprintf(stderr," Couldn't fstat %s (%s?)\n",fn,strerror(errno));
		goto done;
	}
	if(buf.st_size == 0){
		fprintf(stderr," Won't scan empty file\n");
		ret = 0;
		goto done;
	}
	if((map = mmap(NULL,buf.st_size,PROT_READ,MAP_SHARED,fd,0)) == MAP_FAILED){
		fprintf(stderr," Couldn't mmap %s (%s?)\n",fn,strerror(errno));
		goto done;
	}
	if(bonware_prepscan_buffer(fn,map,buf.st_size,&req,&res,1)){
		goto done;
	}
	ret = bonware_scan(&req,&res) | handle_results(fn,&res,1);

done:
	if((map != MAP_FAILED) && munmap(map,buf.st_size)){
		fprintf(stderr," Couldn't unmap %s (%s?)\n",fn,strerror(errno));
		return -1;
	}
	if(fd >= 0 && close(fd)){
		fprintf(stderr," Couldn't close %s (%s?)\n",fn,strerror(errno));
		return -1;
	}
	return ret;
}

static int
daemonv(FILE *out,const char *fmt,...) __attribute__ ((format (printf,2,3)));

static int
daemonv(FILE *out,const char *fmt,...){
	int ret = -1;
	va_list va; 

	if(pthread_mutex_lock(&daemonlock)){
		return -1;
	}
	va_start(va,fmt);
	if(vfprintf(out,fmt,va) < 0){
		fprintf(stderr,"Error writing '%s' to output stream (%s?)\n",fmt,strerror(errno));
	}else if(fflush(out)){
		fprintf(stderr,"Error flushing output stream (%s?)\n",strerror(errno));
	}else{
		ret = 0;
	}
	va_end(va);
	if(pthread_mutex_unlock(&daemonlock)){
		return -1;
	}
	return ret;
}

static int
daemon_out(FILE *out,const char *key,unsigned buflen,int status,
		const char *description,unsigned probability){
	return daemonv(out,"%c|%s|%u|%u|%s"CRLF,status,description,
			probability,buflen,key);
}

static inline int
daemon_status_out(FILE *out,const char *oemapi,const char *oemapieng,
				unsigned ver[3],unsigned engver[3]){
	return daemonv(out,"%c|%s|%u.%u.%u|%s|%u.%u.%u"CRLF,BONDAEMON_STATUS,
			oemapieng,ver[0],ver[1],ver[2],oemapi,
			engver[0],engver[1],engver[2]);
}

static int
filethread(FILE *out,marshal *m){
	SCANMAPI_REQUEST sreq;
	SCANMAPI_RESULT sres;
	int ret;

	if(bonware_prepscan_file(m->path,&sreq,&sres)){
		return daemon_out(out,m->path,m->mlen,BONDAEMON_ERROR,
			"Bontool internal error",100);
	}
	ret = bonware_scan(&sreq,&sres) | handle_results(m->path,&sres,1);
	if(ret < 0){
		return daemon_out(out,m->path,m->mlen,BONDAEMON_ERROR,
			bonware_strerror(sres.ReasonCode),sres.Probability);
	}else if(ret){
		return daemon_out(out,m->path,m->mlen,BONDAEMON_MALWARE,
				sres.Name,sres.Probability);
	}
	return daemon_out(out,m->path,m->mlen,BONDAEMON_CLEAN,"",sres.Probability);
}

static int
shmthread(FILE *out,marshal *m,int complete){
	SCANMAPI_REQUEST sreq;
	SCANMAPI_RESULT sres;
	int ret,fd;

	if((fd = open(m->path,O_RDONLY)) < 0){
		ret = daemon_out(out,m->path,m->mlen,BONDAEMON_ERROR,"open",100);
	}else{
		int mflags = MAP_SHARED
#ifdef MAP_POPULATE
			| MAP_POPULATE
#endif
			;
		void *buf;

		if((buf = mmap(NULL,m->mlen,PROT_READ,mflags,fd,0)) == MAP_FAILED){
			ret = daemon_out(out,m->path,m->mlen,BONDAEMON_ERROR,"mmap",100);
		}else{
		       	if(bonware_prepscan_buffer(m->path,buf,m->mlen,&sreq,&sres,complete)){
				ret = daemon_out(out,m->path,m->mlen,BONDAEMON_ERROR,"Bontool internal error",100);
			}else{
				// handle_results() must be called even if
				// bonware_scan() returns an error!
				ret = bonware_scan(&sreq,&sres) | handle_results(m->path,&sres,complete);
				if(ret < 0){
					ret = daemon_out(out,m->path,m->mlen,BONDAEMON_ERROR,
						bonware_strerror(sres.ReasonCode),sres.Probability);
				}else if(ret){
					ret = daemon_out(out,m->path,m->mlen,BONDAEMON_MALWARE,
						sres.Name,sres.Probability);
				}else{
					ret = daemon_out(out,m->path,m->mlen,BONDAEMON_CLEAN,"",sres.Probability);
				}
			}
			if(munmap(buf,m->mlen)){
				fprintf(stderr,"Couldn't unmap %s at %d (%s?)\n",m->path,fd,strerror(errno));
			}
		}
		if(close(fd)){
			fprintf(stderr,"Couldn't close %s at %d (%s?)\n",m->path,fd,strerror(errno));
		}
	}
	return ret;
}

static inline marshal *
create_marshal(const char *key,char mtype,size_t len){
	marshal *ret;

	if( (ret = malloc(sizeof(*ret))) ){
		strcpy(ret->path,key);
		ret->mtype = mtype;
		ret->next = NULL;
		ret->mlen = len;
	}
	return ret;
}

// key should have already been checked to ensure it's PATH_MAX or less
// characters, not including the '\0' terminator. mtype ought be 's', 'p' or
// 'f' for a shared memory scan, partial shared memory scan, or file scan. we
// maybe ought check that mlen is not greater than the length on disk hrm FIXME
static inline int
enqueue_scan(FILE *out,const char *key,char mtype,size_t mlen){
	marshal *ret;

	if((ret = create_marshal(key,mtype,mlen)) == NULL){
		return daemon_out(out,key,mlen,BONDAEMON_ERROR,"malloc",100);
	}
	pthread_mutex_lock(&daemonlock);
	*enqueue_scans = ret;
	enqueue_scans = &ret->next;
	++outstanding;
	pthread_mutex_unlock(&daemonlock);
	pthread_cond_signal(&daemoncond);
	return 0;
}

static void *
bonthread(void *unsafe_outstream){
	FILE *out = unsafe_outstream;
	marshal *m = NULL;
	int ret;

	pthread_mutex_lock(&daemonlock);
	do{
		while((m = pending_scans) == NULL){
			if(shuttingdown){
				pthread_cond_signal(&daemoncond);
				pthread_mutex_unlock(&daemonlock);
				return NULL;
			}
			pthread_cond_wait(&daemoncond,&daemonlock);
		}
		if((pending_scans = m->next) == NULL){
			enqueue_scans = &pending_scans;
		}
		pthread_mutex_unlock(&daemonlock);
		switch(m->mtype){
			case 's':
				ret = shmthread(out,m,1);
				break;
			case 'p':
				ret = shmthread(out,m,0);
				break;
			case 'f':
				ret = filethread(out,m);
				break;
			default:
				ret = daemon_out(out,m->path,m->mlen,
					BONDAEMON_ERROR,"Invalid command",100);
				break;
		}
		free(m);
		pthread_mutex_lock(&daemonlock);
		--outstanding;
	}while(ret == 0);
	pthread_mutex_unlock(&daemonlock);
	exit(EXIT_FAILURE); // see bug 871; this is a hack, but simple
}

static int
bonware_daemon_status(FILE *out){
	SCANMAPI_STATUS status;		 

	if(bonware_getstatus(&status)){
		fprintf(stderr,"Error getting status\n");
		return -1;
	}
	return daemon_status_out(out,status.OEMAPIVersion,status.OEMEngineVersion,
					status.Version,status.EngineVersion);
}

static int
bonware_daemon(FILE *in,FILE *out,int procs){
	// maximum file name + CRLF + 1-char command + '\0'
	char cmd[PATH_MAX + 4];
	pthread_attr_t attr;
	int ret = -1;

	verprintf(" Detected %d processing units.\n",procs);
	if(pthread_attr_init(&attr)){
		fprintf(stderr,"Couldn't initialize pthread_attr (%s?)\n",strerror(errno));
		return -1;
	}
	if(pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED)){
		fprintf(stderr,"Couldn't initialize pthread_attr (%s?)\n",strerror(errno));
		goto done;
	}
	while(procs--){
		pthread_t tid;

		if(pthread_create(&tid,&attr,bonthread,out)){
			fprintf(stderr,"Couldn't create pthread (%s?)\n",strerror(errno));
			goto done;
		}
	}
	if(bonware_daemon_status(out)){
		goto done;
	}
	while(fgets(cmd,sizeof(cmd),in)){
		char *nl;

		// Error out on too long of an input line -- we don't want to
		// interpret a command in media res.
		if((nl = strrchr(cmd,'\xd')) == NULL){
			fprintf(stderr," Not terminated with CRLF: %s\n",cmd);
			continue;
		}
		if(nl[1] != '\xa'){
			fprintf(stderr," Line too long: %s\n",cmd);
			continue;
		}
		*nl = '\0';
		switch(cmd[0]){
			case 'f':
			case 's':
			case 'p': {
				char *key = cmd + 1;
				int len;
				
				while(isdigit(*key)){
					++key;
				}
				if(*key != ',' || key == cmd + 1){
					fprintf(stderr," Not 'length,key': %s\n",cmd + 1);
					goto done;
				}
				*key = '\0';
				// FIXME rigourize this wretchedness
				len = atoi(cmd + 1);
				if(enqueue_scan(out,key + 1,cmd[0],len)){
					fprintf(stderr,"Couldn't scan %c-type\n",cmd[0]);
					goto done;
				}
				verprintf("Scanning %d at '%s'...\n",len,key + 1);
				break;
			 } case 'r':
				verprintf("Reconfiguring bonware...\n");
				if(cmd[1] != '\0'){
					fprintf(stderr,"'r'econfigure takes no arguments\n");
					goto done;
				}
				if(bonware_reconfig()){
					fprintf(stderr,"Error reconfiguring\n");
					goto done;
				}
				if(bonware_daemon_status(out)){
					goto done;
				}
				break;
			case 'g':{
				if(cmd[1] != '\0'){
					fprintf(stderr,"'g'et status takes no arguments\n");
					goto done;
				}
				if(bonware_daemon_status(out)){
					goto done;
				}
				break;
			}case 'q':
				ret = 0;
				goto done;
			default:
				pthread_mutex_lock(&daemonlock);
				fprintf(out,"Commands:\n"
					"  q -- quit\n"
					"  g -- get status\n"
					"  r -- reload scanmapi\n"
					"  fLength,Filename -- scan first <Length> bytes of <Filename>\n"
					"  pLength,SharedmemId -- scan first <Length> bytes of <SharedmemId>\n"
					"  sLength,SharedmemId -- preview first <Length> bytes of <SharedmemId>\n");
				fprintf(out,"Result codes:\n"
					"  e -- error\n"
					"  c -- clean\n"
					"  i -- infected\n"
					"  s -- status\n");
				pthread_mutex_unlock(&daemonlock);
				break;
		}
	}
	if(ferror(in)){
		fprintf(stderr," Error reading from input (%s?)\n",strerror(errno));
		goto done;
	}
	ret = 0;

done:
	pthread_mutex_lock(&daemonlock);
	shuttingdown = 1;
	while(outstanding){
		fprintf(stderr,"Waiting on %u requests...\n",outstanding);
		pthread_cond_wait(&daemoncond,&daemonlock);
	}
	shuttingdown = 0;
	pthread_mutex_unlock(&daemonlock);
	pthread_attr_destroy(&attr);
	verprintf("All requests cleared, exiting...\n");
	return ret;
}

static int
bonware_status(void){
	SCANMAPI_STATUS res;

	if(bonware_getstatus(&res)){
		return -1;
	}
	verprintf(" Anti-Malware library version %u.%u.%u\n",res.Version[0],
			res.Version[1],res.Version[2]);
	verprintf(" Anti-Malware engine version %u.%u.%u (%u loaded)\n",
			res.EngineVersion[0],res.EngineVersion[1],res.EngineVersion[2],
			res.LoadedEngines);
	return 0;
}

static int
get_numcpus(void){
	long sc;

	if((sc = sysconf(_SC_NPROCESSORS_ONLN)) <= 0){
		return -1;
	}
	// In a multicore setup, use all but 1 of the CPU's
	// FIXME Replace CPU detection with designed use of CPUsets
	if(sc == 1){
		return sc;
	}
	return sc - 1;
}

int main(int argc,char **argv){
	int ret = EXIT_SUCCESS,opt;
	char **cur;

	while((opt = getopt(argc,argv,"v")) >= 0){
		switch(opt){
			case 'v': ++verbose; break;
			default: fprintf(stderr,"Invalid option character: %c\n",opt);
				 usage(argv,EXIT_FAILURE);
		}
	}
	if(argc - optind < 1){
		usage(argv,EXIT_FAILURE);
	}
	verprintf(" Initializing the anti-malware library...\n");
	if(bonware_init(argv[optind],verbose)){
		usage(argv,EXIT_FAILURE);
		return EXIT_FAILURE;
	}
	if(bonware_status()){
		return EXIT_FAILURE;
	}
	cur = argv + optind + 1;
	if(!*cur){
		int procs;

		if((procs = get_numcpus()) < 0){
			return EXIT_FAILURE;
		}
		if(bonware_daemon(stdin,stdout,procs)){
			ret = EXIT_FAILURE;
		}
	}else do{
		verprintf(" Scanning as buffer: %s\n",*cur);
		if(scan_as_buffer(*cur) < 0){
			ret = EXIT_FAILURE;
			break;
		}
	}while(*++cur);
	verprintf(" Shutting down the anti-malware library...\n");
	if(bonware_stop()){
		return EXIT_FAILURE;
	}
	verprintf(" Shut down the anti-malware library!\n");
	return ret;
}
