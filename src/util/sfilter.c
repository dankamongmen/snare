#include <sf_control.h>
#include <util/sfilter.h>
#include <snare/icap/http.h>
#include <snare/icap/request.h>
#include <libdank/utils/text.h>
#include <libdank/utils/string.h>
#include <libdank/utils/rfc2396.h>
#include <libdank/utils/memlimit.h>
#include <libdank/objects/logctx.h>
#include <handler/handler_common.h>

#define LOG_LEVEL SFCL_LOG_LEVEL_INFO
#define LOG_AREA SFCL_LOG_AREA_ALL

typedef struct sfilter_policy { 
	SFCL_Url sfurl;
	SFCL_Handle policy_handle;
	SFCL_Categories categories;
	SFCL_Attributes attributes;
} sfilter_policy;

static SFCL_Handle sfcl_handle,*sfclx = NULL;

static void sfilter_log_cb(SFCL_Log_Level level,SFCL_Log_Area area,const char *msg){
	nag("%d %d %s\n",level,area,msg);
}

static int
sfilter_policy_init_categories(SFCL_Handle sp,SFCL_Categories *scg){
	sfilter_category cat;

	if(SFCL_CategoriesCreate(sp,scg)){
		bitch("Couldn't create SmartFilter categories\n");
		return -1;
	}
	if(SFCL_CategoriesCategoryRemoveAll(sp,*scg)){
		bitch("Couldn't empty SmartFilter categories\n");
		SFCL_CategoriesDestroy(sp,scg);
		return -1;
	}
	for(cat = SFILTER_HANDLERLIST ; cat < SFILTER_MAXLIST ; ++cat){
		if(SFCL_CategoriesCategoryAdd(sp,*scg,cat)){
			bitch("Couldn't add SmartFilter category %d\n",cat);
			SFCL_CategoriesDestroy(sp,scg);
			return -1;
		}
	}
	return 0;
}

static int
sfilter_policy_init_handle(sfilter_policy *sp){
	if(SFCL_LogFunctionSet(sp->policy_handle,sfilter_log_cb)){
		bitch("Couldn't set SmartFilter log function\n");
		return -1;
	}
	if(SFCL_LogLevelSet(sp->policy_handle,LOG_LEVEL,LOG_AREA)){
		bitch("Couldn't set SmartFilter log level\n");
		return -1;
	}
	if(SFCL_AttributesCreate(sp->policy_handle,&sp->attributes)){
		bitch("Couldn't create SmartFilter attributes\n");
		return -1;
	}
	if(SFCL_UrlCreate(sp->policy_handle,&sp->sfurl)){
		bitch("Couldn't create URI\n");
		SFCL_AttributesDestroy(sp->policy_handle,&sp->attributes);
		return -1;
	}
	if(sfilter_policy_init_categories(sp->policy_handle,&sp->categories)){
		SFCL_UrlDestroy(sp->policy_handle,&sp->sfurl);
		SFCL_AttributesDestroy(sp->policy_handle,&sp->attributes);
		return -1;
	}
	return 0;
}

static int
sfilter_policy_init(sfilter_policy *sp){
	if(SFCL_HandleCreate(&sp->policy_handle)){
		bitch("Coudln't create SmartFilter handle\n");
		return -1;
	}
	if(sfilter_policy_init_handle(sp)){
		SFCL_HandleDestroy(&sp->policy_handle);
		return -1;
	}
	return 0;
}

sfilter_policy *sfilter_policy_create(void){
	sfilter_policy *ret;

	if( (ret = Malloc("sfilter policy",sizeof(*ret))) ){
		if(sfilter_policy_init(ret)){
			Free(ret);
			return NULL;
		}
	}
	return ret;
}

int sfilter_policy_adduri(sfilter_policy *sp,const char *url,sfilter_category cat){
	SFCL_Url puri = sp->sfurl;

	if(cat >= SFILTER_MAXLIST){
		bitch("Invalid category (%d >= %d)\n",cat,SFILTER_MAXLIST);
		return -1;
	}
	// Host parameter is not applicable here
	if(SFCL_UrlParse(sp->policy_handle,url,NULL,puri)){
		bitch("Couldn't parse URI %s\n",url);
		return -1;
	}
	if(SFCL_CustomSitesAdd(sp->policy_handle,puri,cat,sp->categories,
				SFCL_CUSTOM_SITES_STATE_FINAL,
				SFCL_CUSTOM_SITES_TYPE_NONE,NULL)){
		bitch("Couldn't add URI: %s\n",url);
		return -1;
	}
	if(SFCL_CustomSitesPost(sp->policy_handle)){
		bitch("Couldn't post URI: %s\n",url);
		return -1;
	}
	return 0;
}

// FIXME this is kind of a bit too slack and crappy for my tastes
static int
set_uri_helper(uri *luri,const char *value,int (*fxn)(uri *,const char *)){
	char *scribble,*toke,*end;

	if((scribble = Strdup(value)) == NULL){
		return -1;
	}
	end = scribble;
	if((toke = carve_token(&end)) == NULL){
		bitch("No usable token in header? (%s)\n",value);
		Free(scribble);
		return -1;
	}
	if(fxn(luri,toke)){
		Free(scribble);
		return -1;
	}
	Free(scribble);
	return 0;
}

// Host argument to UrlParse can be null; it is an ASCIIZ string corresponding
// to the domain name (in HTTP 1.1 and some 1.0, this can be extracted from the
// Host: header). SmartFilter requires, at minimum:
//  * a scheme
//  * a hostname
// Free()ing the return value is the caller's responsibility.
char *sfilter_uri_generate(const icap_state *ictx){
	ustring u = USTRING_INITIALIZER;
	uri *luri = NULL;
	char *rawuri;
	
	rawuri = ictx->encaps.http.rawuri;
	if(is_https(ictx)){
		if((luri = extract_connect_uri(&rawuri)) == NULL){
			goto err;
		}
		if(set_uri_helper(luri,"HTTPS",set_uri_scheme)){
			bitch("No scheme available via %s; can't use smartfilter\n",
					ictx->encaps.http.rawuri);
			goto err;
		}
	}else if((luri = extract_uri(NULL,&rawuri)) == NULL){
		goto err;
	}
	// FIXME should probably be a hard error, but we see bad queries
	if(*rawuri){
		bitch("Warning: extracting URI; retained %s\n",rawuri);
	}
	if(luri->scheme == NULL){
		if(ictx->headers.encapsulated_protocol == NULL ||
		   set_uri_helper(luri,ictx->headers.encapsulated_protocol,set_uri_scheme)){
			bitch("No scheme available via %s; can't use smartfilter\n",
					ictx->encaps.http.rawuri);
			goto err;
		}
	}
	if(luri->host == NULL){
		if(ictx->encaps.http.server == NULL ||
		   set_uri_helper(luri,ictx->encaps.http.server,set_uri_host)){
			bitch("No server available via %s; can't use smartfilter\n",
					ictx->encaps.http.rawuri);
			goto err;
		}
	}
	if(stringize_uri(&u,luri)){
		goto err;
	}
	free_uri(&luri);
	return u.string;

err:
	reset_ustring(&u);
	free_uri(&luri);
	return NULL;
}

// The URI passed must be suitable for SmartFilter -- use
// sfilter_uri_generate() to create one from an icap_http_headers object.
int sfilter_uri_query(sfilter_policy *sp,const char *sfu){
	SFCL_Url puri = sp->sfurl;
	int catcount;

	if(SFCL_UrlParse(sp->policy_handle,sfu,NULL,puri)){
		bitch("URL couldn't be parsed for %s\n",sfu);
		return -1;
	}
	// Last parameter is "methods to skip" (of for instance CGI parameter
	// reading, custom keywords, patterns etc). Since we don't use any of
	// these (save custom sites, which we never want to skip), we pass 0.
	if(SFCL_UrlCategorize(sp->policy_handle,puri,sp->attributes,
				sp->categories,&catcount,0)){
		bitch("Couldn't categorize %s\n",sfu);
		return -1;
	}
	return catcount;
}

void sfilter_policy_destroy(sfilter_policy *sp){
	if(sp){
		if(SFCL_UrlDestroy(sp->policy_handle,&sp->sfurl)){
			bitch("Error destroying SmartFilter URI\n");
		}
		if(SFCL_CategoriesDestroy(sp->policy_handle,&sp->categories)){
			bitch("Error destroying SmartFilter categories\n");
		}
		if(SFCL_AttributesDestroy(sp->policy_handle,&sp->attributes)){
			bitch("Error destroying SmartFilter attributes\n");
		}
		if(SFCL_HandleDestroy(&sp->policy_handle)){
			bitch("Error destroying SmartFilter handle\n");
		}
		Free(sp);
	}
}

static int
sfilter_version_check(SFCL_Handle sfx){
	char desc[SFCL_API_VERSION_DESC_LEN];
	int info;

	if(SFCL_HandleInfoGet(sfx,SFCL_HANDLE_INFO_API_VERSION_DESC,desc)){
		bitch("Couldn't get SmartFilter API version description\n");
		return -1;
	}
	if(SFCL_HandleInfoGet(sfx,SFCL_HANDLE_INFO_API_VERSION_MAJOR,&info)){
		bitch("Couldn't get SmartFilter API major version\n");
		return -1;
	}
	if(info != SFCL_API_VERSION_MAJOR){
		bitch("Version check failure: compiled %d, linked %d\n",
				SFCL_API_VERSION_MAJOR,info);
		return -1;
	}
	if(SFCL_HandleInfoGet(sfx,SFCL_HANDLE_INFO_API_VERSION_MINOR,&info)){
		bitch("Couldn't get SmartFilter API major version\n");
		return -1;
	}
	if(info != SFCL_API_VERSION_MINOR){
		bitch("Version check failure: compiled %d, linked %d\n",
				SFCL_API_VERSION_MINOR,info);
		return -1;
	}
	nag("SmartFilter version check PASSED, %d.%d (%s)\n",
			SFCL_API_VERSION_MAJOR,SFCL_API_VERSION_MINOR,desc);
	return 0;
}

int sfilter_init(void){
	if(SFCL_Init()){
		return -1;
	}
	if(SFCL_HandleCreate(&sfcl_handle)){
		return -1;
	}
	if(sfilter_version_check(sfcl_handle)){
		sfilter_destroy();
		return -1;
	}
	if(SFCL_LogFunctionSet(sfcl_handle,sfilter_log_cb)){
		sfilter_destroy();
		return -1;
	}
	if(SFCL_LogLevelSet(sfcl_handle,LOG_LEVEL,LOG_AREA)){
		sfilter_destroy();
		return -1;
	}
	sfclx = &sfcl_handle;
	nag("Initialized SmartFilter\n");
	return 0;
}

int sfilter_destroy(void){
	int ret = 0;

	if(sfclx){
		ret |= SFCL_ListUnload(*sfclx);
		ret |= SFCL_HandleDestroy(sfclx);
		ret |= SFCL_Shutdown();
		sfclx = NULL;
	}
	nag("Destroyed SmartFilter\n");
	return ret;
}

// We only see X-Encapsulated-Protocol from WebWasher; squid sends us CONNECT
// https sans scheme or that header. Assume, for all CONNECT, that the protocol
// is https; is it safe...?
int is_https(const struct icap_state *is){
	// Ensured present in reqmod_handler() sanity checks
	return !strcasecmp(is->encaps.http.method,"CONNECT");
}
