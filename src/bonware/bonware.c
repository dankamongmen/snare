#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <bonware/bonware.h>
#include <antimalware/scanmapi.h>

const char *bonware_strerror(unsigned err){
	switch(err){
		case SCANMAPI_SUCCESS:
			return "Success";
		case SCANMAPI_ERROR_INVALIDPARAM:
			return "Invalid parameter to SCANMAPI";
		case SCANMAPI_ERROR_FILENOTFOUND:
			return "File not found or couldn't be mapped by SCANMAPI";
		case SCANMAPI_ERROR_FILETOOLARGE:
			return "File too large for SCANMAPI";
		case SCANMAPI_ERROR_LOADFAILED:
			return "Couldn't load SCANMAPI databases";
		case SCANMAPI_ERROR_NEEDMOREDATA:
			return "Insufficient data for SCANMAPI";
		case SCANMAPI_ERROR_NOTINITIALIZED:
			return "SCANMAPI_Initialize() hasn't been called";
		case SCANMAPI_ERROR_UNKNOWN:
			return "Unknown error in SCANMAPI";
		default:
			return "Invalid result code for SCANMAPI";
	}
}

int bonware_init(const char *path,int uselog){
	SCANMAPI_INIT scanmapi;
	unsigned ret;

	if(strlen(path) >= SCANMAPI_MAX_STRLEN){
		fprintf(stderr,"Filename too long: %s\n",path);
		return -1;
	}
	memset(&scanmapi,0,sizeof(scanmapi));
	// See 3.1 of Embedders' Guide, 3.1.1 for flags
	scanmapi.Revision = SCANMAPI_REVISION;
	scanmapi.Size = sizeof(scanmapi);
	// scanmapi.Flags = SCANMAPI_INIT_ALLOWFALLBACK;
	if(uselog){
		printf("Writing log to /tmp/scanm.log\n");
		scanmapi.Flags |= SCANMAPI_INIT_WRITELOG;
	}
	strcpy(scanmapi.Path,path);
	if((ret = SCANMAPI_Initialize(&scanmapi)) != SCANMAPI_SUCCESS){
		fprintf(stderr,"Error %d in SCANMAPI_Initialize (%s?)\n",ret,bonware_strerror(ret));
		return -1;
	}
	return 0;
}

int bonware_reconfig(void){
	unsigned ret;

	if((ret = SCANMAPI_ReInitialize()) != SCANMAPI_SUCCESS){
		fprintf(stderr,"Error %d in SCANMAPI_ReInitialize (%s?)\n",ret,bonware_strerror(ret));
		return -1;
	}
	return 0;
}

// See 3.2 of Embedders' Guide. Once we actually call SCANMAPI_Scan(), we must
// call SCANMAPI_Free(), even on an error. So that we needn't introduce some
// distinguishing sentinel into our API, we instead separate prep from exec...
int bonware_prepscan(const char *fname,const unsigned char *buf,unsigned buflen,
			SCANMAPI_REQUEST *req,SCANMAPI_RESULT *res,int complete){
	if(!!buflen != !!buf){
		fprintf(stderr,"Provided only one of buf, buflen (%p, %u)\n",buf,buflen);
		return -1;
	}
	memset(res,0,sizeof(*res));
	res->Revision = SCANMAPI_REVISION;
	res->Size = sizeof(*res);
	req->Revision = SCANMAPI_REVISION;
	req->Size = sizeof(*req);
	req->Flags = SCANMAPI_REQUEST_USESIGNATURES |
		SCANMAPI_REQUEST_USEHEURISTICS_BASE |
		(complete ? 0 : SCANMAPI_REQUEST_SKIPSAFEFORMATS | SCANMAPI_REQUEST_SCANPARTIAL);
	req->Buffer = buf;
	req->BufferLength = buflen;
	req->CustomIfaces = NULL;
	req->MediaType[0] = '\0';
	if(buf){
		const char *relpath;

		if((relpath = strrchr(fname,'/')) == NULL){
			relpath = fname;
		}
		if(strlen(relpath) >= SCANMAPI_MAX_STRLEN){
			fprintf(stderr,"Filename too long: %s\n",fname);
			return -1;
		}
		strcpy(req->Name,relpath); // relative filename required for buf
		// USEHEURISTICS_BEHAVIORAL is only supported for membufs
		req->Flags |= SCANMAPI_REQUEST_USEHEURISTICS_BEHAVIORAL;
	}else{
		char abspath[PATH_MAX];

		if(realpath(fname,abspath) == NULL){
			fprintf(stderr,"Couldn't resolve path to %s (%s?)\n",
					fname,strerror(errno));
			return -1;
		}
		if(strlen(abspath) >= SCANMAPI_MAX_STRLEN){
			fprintf(stderr,"Filename too long: %s\n",abspath);
			return -1;
		}
		strcpy(req->Name,abspath); // relative filename required for buf
		req->Flags |= SCANMAPI_REQUEST_SCANLOCALFILE;
	}
	return 0;
}

int bonware_scan(SCANMAPI_REQUEST *req,SCANMAPI_RESULT *res){
	unsigned ret;

	if((ret = SCANMAPI_Scan(req,res)) != SCANMAPI_SUCCESS &&
			ret != SCANMAPI_ERROR_NEEDMOREDATA){
		fprintf(stderr,"Error %d in SCANMAPI_Scan (%s?)\n",
				ret,bonware_strerror(ret));
		return -1;
	}
	return 0;
}

int bonware_free_result(SCANMAPI_RESULT *res){
	unsigned ret;

	if((ret = SCANMAPI_Free(res)) != SCANMAPI_SUCCESS){
		fprintf(stderr,"Error %u in SCANMAPI_Free (%s?)\n",ret,bonware_strerror(ret));
		return -1;
	}
	return 0;
}

int bonware_getstatus(SCANMAPI_STATUS *res){
	unsigned ret;

	res->Revision = SCANMAPI_REVISION;
	res->Size = sizeof(*res);
	if((ret = SCANMAPI_GetStatus(res)) != SCANMAPI_SUCCESS){
		fprintf(stderr,"Error %u in SCANMAPI_GetStatus (%s?)\n",ret,bonware_strerror(ret));
		return -1;
	}
	if(res->Status != SCANMAPI_SUCCESS){
		fprintf(stderr,"SCANMAPI is improperly initialized (%s?)\n",bonware_strerror(ret));
		return -1;
	}
	return 0;
}

int bonware_stop(void){
	unsigned ret;

	if((ret = SCANMAPI_Shutdown()) != SCANMAPI_SUCCESS){
		fprintf(stderr,"Error %u in SCANMAPI_Shutdown (%s?)\n",ret,bonware_strerror(ret));
		return -1;
	}
	return 0;
}
