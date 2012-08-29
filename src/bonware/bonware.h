#ifndef BONWARE_BONWARE_H
#define BONWARE_BONWARE_H

#include <antimalware/scanmapi.h>

// If a non-zero integer is passed, the SCANMAPI_INIT_WRITELOG flag will be
// used, causing copious output to be generated at /tmp/scanm.log (this is as
// good as the debugging facilities get). The string must contain a path naming
// a valid updates/ directory for this architecture. Blocks on the
// initialization process in its entirety, which can be several seconds.
int bonware_init(const char *,int);
int bonware_reconfig(void);

// Blocks on the shutdown, which can be several seconds.
int bonware_stop(void);

int bonware_prepscan(const char *,const unsigned char *,unsigned,
			SCANMAPI_REQUEST *,SCANMAPI_RESULT *,int);
int bonware_scan(SCANMAPI_REQUEST *,SCANMAPI_RESULT *);
int bonware_free_result(SCANMAPI_RESULT *);
int bonware_getstatus(SCANMAPI_STATUS *);

// Users must call bonware_free_result() following a successful call! Partial
// scans cannot be performed on files, only on shared memory.
static inline int
bonware_prepscan_file(const char *fn,SCANMAPI_REQUEST *req,SCANMAPI_RESULT *res){
	return bonware_prepscan(fn,NULL,0,req,res,1);
}

// Users must call bonware_free_result() following a successful call!
static inline int
bonware_prepscan_buffer(const char *fname,const unsigned char *buf,
			unsigned buflen,SCANMAPI_REQUEST *req,
			SCANMAPI_RESULT *res,int complete){
	return bonware_prepscan(fname,buf,buflen,req,res,complete);
}

// Turn a result code into a scanmapi diagnostic string.
const char *bonware_strerror(unsigned);

#endif
