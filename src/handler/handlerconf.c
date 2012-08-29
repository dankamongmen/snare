#include <limits.h>
#include <snare/config.h>
#include <libxml/parser.h>
#include <handler/handler.h>
#include <libdank/utils/hex.h>
#include <handler/handlerconf.h>
#include <libdank/utils/string.h>
#include <libdank/utils/memlimit.h>
#include <libdank/objects/logctx.h>
#include "u16_set.h"
#include "string_list.h"
#include "string_map.h"

#define HCONF_CONFIG_ELEM "policyfile"
#define HCONF_AUTH_TOKEN_HMAC_KEY "auth_token_hmac_key"
#define HCONF_AUTH_TIME_WINDOW "auth_time_window"
#define HCONF_BYPASS_TIME_WINDOW "bypass_time_window"
#define HCONF_BONTOOL_ELEM "bontool"
#define HCONF_BONSIGS_ELEM "bonsigs"
#define HCONF_PROXYAUTH_NONCE_DIFF "proxyauth_nonce_diff"
#define HCONF_PROXYAUTH_HTML "proxyauth_html"
#define HCONF_VID_SIZE "proxyauth_vid_size"
#define HCONF_GENERIC_PAC "generic_pac"
#define HCONF_ALLOWED_PORT "allow_port"
#define HCONF_NTLM_EXCL_UA "ntlm_exclude_ua"
#define HCONF_COOKIE_EXCL_UA "cookie_exclude_ua"
#define HCONF_TESTURI_MAP "testuri_map"

#define DEFAULT_HMAC_HEX "6f6854659990d6ff2556508fdd25a87e51673d69"
#define DEFAULT_AUTH_TIME_WINDOW 86400	// 1 day = 86400 seconds
#define DEFAULT_BYPASS_TIME_WINDOW 3600	// 1 hour = 3600 seconds
#define DEFAULT_PROXYAUTH_NONCE_DIFF 500
#define DEFAULT_PROXYAUTH_HTML \
  "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\n"	\
  " \"http://www.w3.org/TR/html4/loose.dtd\">\n" \
  "<html><body><h1>Authorization Required</h1></body></html>"
#define DEFAULT_VID_SIZE 1000000
#define DEFAULT_GENERIC_PAC \
  "function FindProxyForURL(url, host) { return \"DIRECT\"; }"

typedef struct repconf {
	char *hostname;
} repconf;

// We want to track whether the HMAC key was explicitly set or not (we don't
// write it out unless it was set, and we do if it was -- even if it the
// default key was explicitly set). Thus, a memcmp() is insufficient, and thus
// the purpose of explicit_hmackey. hconf is always valid (default is used).
typedef struct handlerconf {
	repconf repperconf;
	int explicit_hmackey;
	char policyfile[PATH_MAX];
#define add_conf_uri(tagname, varname) char * varname;
#include "handlerconf_uris.h"
#undef add_conf_uri
	unsigned char hmackey[HMAC_KEY_LEN];
	char *auth_token_hmac_key;
	long auth_time_window;
	long bypass_time_window;
	char *bontool_path,*bontool_sigs;
	unsigned int proxyauth_nonce_diff;
	char *proxyauth_html;
	unsigned int vid_size;
	char *generic_pac;
	struct u16set *allowed_ports;
	struct strlst *ntlm_excluded_uas;
	struct strlst *cookie_excluded_uas;
	struct strmap *testuri_map;
} handlerconf;

// FIXME if we set this to static, as it seems it ought be, configuration fails
// due to the changes made not being seen by accessors in this function...odd!!
const handlerconf *handler_state = NULL;

void free_bassdrum_config(handlerconf *hconf){
	if(hconf){
#define add_conf_uri(tagname, varname) Free(hconf->varname);
#include "handlerconf_uris.h"
#undef add_conf_uri
		Free(hconf->repperconf.hostname);
		Free(hconf->auth_token_hmac_key);
		Free(hconf->bontool_path);
		Free(hconf->bontool_sigs);
		Free(hconf->proxyauth_html);
		Free(hconf->generic_pac);
		u16set_delete(hconf->allowed_ports);
		strlst_delete(hconf->ntlm_excluded_uas);
		strlst_delete(hconf->cookie_excluded_uas);
		strmap_delete(hconf->testuri_map);
		Free(hconf);
	}
}

static int
use_repper_config(repconf *rctx,const xmlNodePtr rconf){
	if(rconf->children){
		if( (rctx->hostname = Strdup((const char *)rconf->children->content)) ){
			return 0;
		}
	}
	return -1;
}

static handlerconf *
use_handler_config(xmlNodePtr hconf){
	handlerconf *hctx;
	int ret = 0;

	if((hctx = Malloc("handler config state",sizeof(*hctx))) == NULL){
		return NULL;
	}
	memset(hctx,0,sizeof(*hctx));
	if(hextoascii(DEFAULT_HMAC_HEX,hctx->hmackey,EOF,sizeof(hctx->hmackey)) == NULL){
		bitch("Default HMAC key invalid (%zub)\n",strlen(DEFAULT_HMAC_HEX));
		ret = -1;
	}
	if( (hconf = hconf->children) ){
		do{
			if(hconf->type != XML_ELEMENT_NODE){
				continue;
			}
			if(xmlStrcmp(hconf->name,BAD_CAST("repperhost")) == 0){
				ret |= use_repper_config(&hctx->repperconf,hconf);
			}else if(xmlStrcmp(hconf->name,BAD_CAST("hmackey")) == 0){
				if(hconf->children){
					const char *key = (const char *)hconf->children->content;

					if(hextoascii(key,hctx->hmackey,EOF,sizeof(hctx->hmackey)) == NULL){
						ret = -1;
					}else{
						hctx->explicit_hmackey = 1;
					}
				}
			}else if(xmlStrcmp(hconf->name,BAD_CAST(HCONF_CONFIG_ELEM)) == 0){
				if(hconf->children){
					const char *pfile = (const char *)hconf->children->content;

					if(strlen(pfile) >= sizeof(hctx->policyfile)){
						bitch("Pathname too long: %s\n",pfile);
						ret = -1;
					}else{
						strcpy(hctx->policyfile,pfile);
					}
				}
			}
#define add_conf_uri(tagname, varname) \
else if(xmlStrcmp(hconf->name,BAD_CAST(#tagname)) == 0){ \
	if(hconf->children){ \
		const char *turi = (const char *)hconf->children->content; \
		if(hctx->varname){ \
			bitch(#tagname " was provided twice\n"); \
		}else if((hctx->varname = Strdup(turi)) == NULL){ \
			ret = -1; \
		} \
	} \
}
#include "handlerconf_uris.h"
#undef add_conf_uri

			else if(xmlStrcmp(hconf->name,BAD_CAST(HCONF_AUTH_TOKEN_HMAC_KEY)) == 0){
				if(hconf->children){
					const char *str = (const char *)hconf->children->content;

					if(hctx->auth_token_hmac_key){
						bitch("Auth token hmac key was provided twice\n");
					}else if((hctx->auth_token_hmac_key = Strdup(str)) == NULL){
						ret = -1;
					}
				}
			}else if(xmlStrcmp(hconf->name,BAD_CAST(HCONF_AUTH_TIME_WINDOW)) == 0){
				if(hconf->children){
					const char *str = (const char *)hconf->children->content;

					if(hctx->auth_time_window){
						// this is not very clean as you can provide it multiple times with a zero value
						bitch("Auth time window was provided twice\n");
					} else {
						char *ep;
						long tw = strtol(str, &ep, 10);
						if(ep[0]) {
							ret = -1;
						}
						hctx->auth_time_window = tw;
					}
				}
			}else if(xmlStrcmp(hconf->name,BAD_CAST(HCONF_BYPASS_TIME_WINDOW)) == 0){
				if(hconf->children){
					const char *str = (const char *)hconf->children->content;

					if(hctx->bypass_time_window){
						// this is not very clean as you can provide it multiple times with a zero value
						bitch("Bypass time window was provided twice\n");
					} else {
						char *ep;
						long tw = strtol(str, &ep, 10);
						if(ep[0]) {
							ret = -1;
						}
						hctx->bypass_time_window = tw;
					}
				}
			}else if(xmlStrcmp(hconf->name,BAD_CAST(HCONF_PROXYAUTH_NONCE_DIFF)) == 0){
				if(hconf->children){
					const char *str = (const char *)hconf->children->content;

					if(hctx->proxyauth_nonce_diff){
						// this is not very clean as you can provide it multiple times with a zero value
						bitch("Proxyauth_nonce_diff was provided twice\n");
					} else {
						char *ep;
						unsigned int i = (unsigned int)strtoul(str, &ep, 10);
						if(ep[0]) {
							ret = -1;
						}
						hctx->proxyauth_nonce_diff = i;
					}
				}
			}else if(xmlStrcmp(hconf->name,BAD_CAST(HCONF_VID_SIZE)) == 0){
				if(hconf->children){
					const char *str = (const char *)hconf->children->content;

					if(hctx->vid_size){
						// this is not very clean as you can provide it multiple times with a zero value
						bitch(HCONF_VID_SIZE " was provided twice\n");
					} else {
						char *ep;
						unsigned int i = (unsigned int)strtoul(str, &ep, 10);
						if(ep[0]) {
							ret = -1;
						}
						hctx->vid_size = i;
					}
				}
			}else if(xmlStrcmp(hconf->name,BAD_CAST(HCONF_ALLOWED_PORT)) == 0){
				if(hconf->children){
					const char *str = (const char *)hconf->children->content;
					char *ep;
					uint16_t u = (unsigned int)strtoul(str, &ep, 10);
					if(ep[0]) {
						ret = -1;
						break;
					}
					if(!hctx->allowed_ports) {
					  if(!(hctx->allowed_ports = u16set_new())) {
					    ret = -1;
					    break;
					  }
					}
					u16set_add(hctx->allowed_ports, u);
				}
			}else if(xmlStrcmp(hconf->name,BAD_CAST(HCONF_NTLM_EXCL_UA)) == 0){
				if(hconf->children){
					const char *str = (const char *)hconf->children->content;

					if(!hctx->ntlm_excluded_uas) {
					  if(!(hctx->ntlm_excluded_uas = strlst_new())) {
					    ret = -1;
					    break;
					  }
					}
					strlst_add(hctx->ntlm_excluded_uas, str);
				}
			}else if(xmlStrcmp(hconf->name,BAD_CAST(HCONF_COOKIE_EXCL_UA)) == 0){
				if(hconf->children){
					const char *str = (const char *)hconf->children->content;

					if(!hctx->cookie_excluded_uas) {
					  if(!(hctx->cookie_excluded_uas = strlst_new())) {
					    ret = -1;
					    break;
					  }
					}
					strlst_add(hctx->cookie_excluded_uas, str);
				}
			}else if(xmlStrcmp(hconf->name,BAD_CAST(HCONF_TESTURI_MAP)) == 0){
				if(hconf->children){
					const char *str = (const char *)hconf->children->content;
					char *s0 = Strdup(str), *s1 = s0, *s2;
					
					ret = -1;

					if(!s0) {
					  goto testuri_map_cleanup;
					}

					if(!hctx->testuri_map) {
					  if(!(hctx->testuri_map = strmap_new())) {
					    goto testuri_map_cleanup;
					  }
					}

					s2 = strsep(&s1, "|");
					if(!s2 || !s1) {
					  goto testuri_map_cleanup;
					}

					strmap_add(hctx->testuri_map, s2, s1);
					nag("Mapping local test URI [%s] to [%s]\n", s2, s1);
					ret = 0;
				testuri_map_cleanup:
					Free(s0);
				}

			}else if(xmlStrcmp(hconf->name,BAD_CAST(HCONF_BONTOOL_ELEM)) == 0){
				if(hconf->children){
					const char *path = (const char *)hconf->children->content;

					ret = -1;
					if(hctx->bontool_path){
						bitch("bontool path was provided twice\n");
					/*}else if(path[0] != '/'){
						bitch("bontool was not an absolute path\n");*/
					}else if( (hctx->bontool_path = Strdup(path)) ){
						ret = 0;
					}
				}
			}else if(xmlStrcmp(hconf->name,BAD_CAST(HCONF_BONSIGS_ELEM)) == 0){
				if(hconf->children){
					const char *path = (const char *)hconf->children->content;

					ret = -1;
					if(hctx->bontool_sigs){
						bitch("bonsigs was provided twice\n");
					/*}else if(path[0] != '/'){
						bitch("bonsigs was not an absolute path\n");*/
					}else if( (hctx->bontool_sigs = Strdup(path)) ){
						ret = 0;
					}
				}
			}else if(xmlStrcmp(hconf->name,BAD_CAST(HCONF_PROXYAUTH_HTML)) == 0){
				if(hconf->children){
					const char *str = (const char *)hconf->children->content;

					ret = -1;
					if(hctx->proxyauth_html){
						bitch("proxyauth_html was provided twice\n");
					}else if( (hctx->proxyauth_html = Strdup(str)) ){
						ret = 0;
					}
				}
			}else if(xmlStrcmp(hconf->name,BAD_CAST(HCONF_GENERIC_PAC)) == 0){
				if(hconf->children){
					const char *str = (const char *)hconf->children->content;

					ret = -1;
					if(hctx->generic_pac){
						bitch(HCONF_GENERIC_PAC " was provided twice\n");
					}else if( (hctx->generic_pac = Strdup(str)) ){
						ret = 0;
					}
				}
			}
		}while(!ret && (hconf = hconf->next) );
	}
	if(ret){
		free_bassdrum_config(hctx);
		hctx = NULL;
	}else{
		const handlerconf *oldhctx;

		oldhctx = handler_state;
		handler_state = hctx;
		if(rep_init()){
			free_bassdrum_config(hctx);
			handler_state = oldhctx;
			hctx = NULL;
		}
	}
	return hctx;
}

static int
stringize_repper_config(ustring *u,const repconf *rconf){
	if(rconf->hostname){
	#define REPPER_CONFIG_ELEM "repperconfig"
		if(printUString(u,"<"REPPER_CONFIG_ELEM">") < 0){
			return -1;
		}
		#define HN_CONFIG_ELEM "hostname"
		if(printUString(u,"<"HN_CONFIG_ELEM">") < 0){
			return -1;
		}
		if(printUString(u,"%s",rconf->hostname) < 0){
			return -1;
		}
		if(printUString(u,"</"HN_CONFIG_ELEM">") < 0){
			return -1;
		}
		#undef HN_CONFIG_ELEM
		if(printUString(u,"</"REPPER_CONFIG_ELEM">") < 0){
			return -1;
		}
	}
	#undef RESPMOD_CONFIG_ELEM
	return 0;
}

int stringize_bassdrum_config(ustring *u,const handlerconf *hconf){
	if(hconf){
#define add_conf_uri(tagname, varname) \
	if(hconf->varname) { \
		if(printUString(u,"<" #tagname ">%s</" #tagname ">",hconf->varname) < 0){ \
			return -1; \
		} \
	}
#include "handlerconf_uris.h"
#undef add_conf_uri
		if(hconf->policyfile){
			if(printUString(u,"<"HCONF_CONFIG_ELEM">%s</"HCONF_CONFIG_ELEM">",hconf->policyfile) < 0){
				return -1;
			}
		}
		if(hconf->explicit_hmackey){
			char key[2 * sizeof(hconf->hmackey) + 1];

			#define HK_CONFIG_ELEM "hmackey"
			asciitohex(hconf->hmackey,key,EOF,sizeof(hconf->hmackey));
			if(printUString(u,"<"HK_CONFIG_ELEM">") < 0){
				return -1;
			}
			if(printUString(u,"%s",key) < 0){
				return -1;
			}
			if(printUString(u,"</"HK_CONFIG_ELEM">") < 0){
				return -1;
			}
			#undef HK_CONFIG_ELEM
		}
		if(hconf->bontool_path){
			if(printUString(u,"<"HCONF_BONTOOL_ELEM">%s</"HCONF_BONTOOL_ELEM">",hconf->bontool_path) < 0){
				return -1;
			}
		}
		if(hconf->bontool_sigs){
			if(printUString(u,"<"HCONF_BONTOOL_ELEM">%s</"HCONF_BONTOOL_ELEM">",hconf->bontool_sigs) < 0){
				return -1;
			}
		}
		if(stringize_repper_config(u,&hconf->repperconf)){
			return -1;
		}
	}
	return 0;
}

// path must be of size PATH_MAX
void get_handler_conf(char *path){
	if(handler_state){ // FIXME
		strcpy(path,handler_state->policyfile);
	}else{
		*path = '\0';
	}
}

// hmackey must provide HMAC_KEY_LEN bytes for writing
void get_hmac_key(void *hmackey){
	if(handler_state){
		memcpy(hmackey,handler_state->hmackey,sizeof(handler_state->hmackey));
	}else{
		if(hextoascii(DEFAULT_HMAC_HEX,hmackey,EOF,sizeof(hmackey)) == NULL){
			bitch("Default HMAC key invalid (%zub)\n",strlen(DEFAULT_HMAC_HEX));
		}
	}
}

char *get_repper_server(void){
	if(handler_state && handler_state->repperconf.hostname){
		return Strdup(handler_state->repperconf.hostname);
	}
	return NULL;
}

char *get_bontool_path(void){
	if(handler_state && handler_state->bontool_path){
		return Strdup(handler_state->bontool_path);
	}
	return NULL;
}

char *get_bontool_sigs(void){
	if(handler_state && handler_state->bontool_sigs){
		return Strdup(handler_state->bontool_sigs);
	}
	return NULL;
}

#define add_conf_uri(tagname, varname) \
char *get_ ## varname(void){ \
	return (handler_state && handler_state->varname) ? \
		Strdup(handler_state->varname) : NULL; \
}
#include "handlerconf_uris.h"
#undef add_conf_uri

// FIXME very suboptimal! insert these into smartfilter or an automaton
#define add_conf_uri(tagname, varname) \
int cmp_ ## varname(const char *uri){ \
	return handler_state && handler_state->varname && \
		(strcasecmp(handler_state->varname,uri) == 0); \
}
#include "handlerconf_uris.h"
#undef add_conf_uri

#define add_conf_uri(tagname, varname) \
size_t cmpn_ ## varname(const char *uri){ \
	if(handler_state && handler_state->varname) { \
		size_t len = strlen(handler_state->varname); \
		if((strncasecmp(handler_state->varname,uri,len) == 0)) { \
			return len; \
		} else { \
			return 0; \
		} \
	} else { \
		return 0; \
	} \
}
#include "handlerconf_uris.h"
#undef add_conf_uri

char *get_auth_token_hmac_key(void){
	if(!handler_state || !handler_state->auth_token_hmac_key){
		return NULL;
	}
	return Strdup(handler_state->auth_token_hmac_key);
}

long get_auth_time_window(void){
	if(!handler_state || !handler_state->auth_time_window){
		return DEFAULT_AUTH_TIME_WINDOW;
	}
	return handler_state->auth_time_window;
}

long get_bypass_time_window(void){
	if(!handler_state || !handler_state->bypass_time_window){
		return DEFAULT_BYPASS_TIME_WINDOW;
	}
	return handler_state->bypass_time_window;
}

unsigned int get_proxyauth_nonce_diff(void){
	if(!handler_state || !handler_state->proxyauth_nonce_diff){
		return DEFAULT_PROXYAUTH_NONCE_DIFF;
	}
	return handler_state->proxyauth_nonce_diff;
}

const char *get_proxyauth_html(void){
	if(!handler_state || !handler_state->proxyauth_html){
		return DEFAULT_PROXYAUTH_HTML;
	}
	return handler_state->proxyauth_html;
}

unsigned int get_vid_size(void){
	if(!handler_state || !handler_state->vid_size){
		return DEFAULT_VID_SIZE;
	}
	return handler_state->vid_size;
}

const char *get_generic_pac(void){
	if(!handler_state || !handler_state->generic_pac){
		return DEFAULT_GENERIC_PAC;
	}
	return handler_state->generic_pac;
}

int is_allowed_port(uint16_t port) {
  if(!handler_state || !handler_state->allowed_ports) {
    return -1;
  }
  if(u16set_isempty(handler_state->allowed_ports)) {
    // If no ports are configured, allow all ports
    return -1;
  }
  return u16set_contains(handler_state->allowed_ports, port);
}

int is_ntlm_excl_ua(const char *ua) {
  if(!handler_state || !handler_state->ntlm_excluded_uas) {
    // No exclusions, return false
    return 0;
  }
  return strlst_substr_contains(handler_state->ntlm_excluded_uas, ua);
}

int is_cookie_excl_ua(const char *ua) {
  if(!handler_state || !handler_state->cookie_excluded_uas) {
    // No exclusions, return false
    return 0;
  }
  return strlst_substr_contains(handler_state->cookie_excluded_uas, ua);
}

const char *testuri_lookup(const char *testuri) {
  if(!handler_state || !handler_state->testuri_map) {
    return 0;
  }
  return strmap_lookup(handler_state->testuri_map, testuri);
}

static const handler_config_interface bassdrum_config_interface = { 
	.hcb = use_handler_config,
	.scb = stringize_bassdrum_config,
	.fcb = free_bassdrum_config,
};

const handler_interface hapi = {
	.oqueuefxn = r_handler,
	.finalfxn = rep_destroy,
	.hci = &bassdrum_config_interface,
};
