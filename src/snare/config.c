#include <libxml/tree.h>
#include <snare/poller.h>
#include <snare/config.h>
#include <snare/threads.h>
#include <snare/modules.h>
#include <libxml/parser.h>
#include <snare/icap/http.h>
#include <snare/icap/stats.h>
#include <libdank/utils/text.h>
#include <libdank/utils/time.h>
#include <libdank/utils/parse.h>
#include <libdank/utils/dlsym.h>
#include <libdank/utils/string.h>
#include <libdank/utils/syswrap.h>
#include <libdank/utils/memlimit.h>
#include <libdank/objects/lexers.h>
#include <libdank/objects/portset.h>
#include <libdank/objects/crlfreader.h>
#include <libdank/modules/fileconf/sbox.h>
#include <libdank/modules/ctlserver/ctlserver.h>

#define XMLTAG_SMTP		"smtp"
#define XMLTAG_HTTP		"http"
#define XMLTAG_ICAP		"icap"
#define XMLTAG_PORT		"port"
#define XMLTAG_SNARE		"snare"
#define XMLTAG_HCONF		"handlerconf"
#define XMLTAG_URIPATH		"uripath"
#define XMLTAG_SHMPREFIX	"shmprefix"
#define DEFAULT_SMTP_PORT	25
#define DEFAULT_ICAP_PORT	1344
#define DEFAULT_HTTP_PORT	80

typedef struct icap_config {
	uint16_t port;
	char *respmod_uri,*reqmod_uri,*shmprefix;
	struct handlerconf *handlerconf;
	void *module;
	const handler_interface *handler_api;
} icap_config;

typedef struct http_config {
	uint16_t port;
} http_config;

typedef struct smtp_config {
	uint16_t port;
} smtp_config;

typedef struct snare_config {
	smtp_config sctx;
	http_config hctx;
	icap_config ictx;
} snare_config;

static snare_config conf;

static int
srv_icap_stats_dump(cmd_state *cs __attribute__ ((unused))){
	int ret = 0;

	block_all_pollers();
	ret |= dump(stringize_icap_stats);
	unblock_all_pollers();
	return ret;
}

static int
srv_icap_stats_clear(cmd_state *cs __attribute__ ((unused))){
	timenag("Clearing ICAP stats\n");
	block_all_pollers();
	clear_icap_stats();
	unblock_all_pollers();
	timenag("Cleared ICAP stats\n");
	return 0;
}

static int
unload_icap_module(icap_config *ictx){
	int ret = 0;

	if(ictx->module){
		if(ictx->handler_api){
			if(ictx->handler_api->finalfxn){
				ret |= ictx->handler_api->finalfxn();
			}
			if(ictx->handler_api->hci && ictx->handler_api->hci->fcb){
				ictx->handler_api->hci->fcb(ictx->handlerconf);
			}
			ictx->handler_api = NULL;
		}
		ret |= Dlclose(ictx->module);
		ictx->module = NULL;
	}
	return ret;
}

static void
free_icap_config(icap_config *ictx){
	Free(ictx->reqmod_uri);
	Free(ictx->respmod_uri);
	Free(ictx->shmprefix);
	unload_icap_module(ictx);
	memset(ictx,0,sizeof(*ictx));
}

static void
free_smtp_config(smtp_config *sctx){
	memset(sctx,0,sizeof(*sctx));
}

static void
free_http_config(http_config *hctx){
	memset(hctx,0,sizeof(*hctx));
}

static void
free_snare_config(snare_config *sctx){
	free_smtp_config(&sctx->sctx);
	free_icap_config(&sctx->ictx);
	free_http_config(&sctx->hctx);
}

static int
use_uri(char **dst,const xmlChar *src){
	nag("Using URI %s\n",src);
	*dst = /*xml*/Strdup((const char *)src);
	return 0;
}

static int
use_module_config(icap_config *ictx,xmlNodePtr xn){
	const char *errstr;

	if(!xn->children || !xn->children->content){
		return -1;
	}
	if(ictx->module){
		bitch("Only one module at a time is currently supported\n");
		return -1;
	}
	if((ictx->module = Dlopen((const char *)xn->children->content,RTLD_NOW)) == NULL){
		return -1;
	}
	if((ictx->handler_api = Dlsym(ictx->module,"hapi",&errstr)) == NULL){
		bitch("Couldn't look up hapi identifier in %s\n",xn->children->content);
		unload_icap_module(ictx);
		return -1;
	}
	nag("Loaded module: %s\n",xn->children->content);
	return 0;
}

static int
use_reqmod_config(icap_config *ictx,xmlNodePtr xn){
	int ret = 0;

	if((xn = xn->children) == NULL){
		return -1;
	}
	do{
		if(xmlStrcmp(xn->name,(const unsigned char *)XMLTAG_URIPATH) == 0){
			if(xn->children){
				ret |= use_uri(&ictx->reqmod_uri,xn->children->content);
			}
		}
	}while( (xn = xn->next) );
	return ret;
}

static int
use_port_config(uint16_t *tcpport,xmlNodePtr xn){
	const char *port;

	if((xn = xn->children) == NULL){
		return -1;
	}else if(xn->type != XML_TEXT_NODE){
		return -1;
	}
	port = (const char *)xn->content;
	if(lex_u16((const char **)&port,tcpport) < 0){
		return -1;
	}
	return 0;
}

static int
use_shm_prefix(icap_config *ictx,xmlNodePtr xn){
	if((xn = xn->children) == NULL){
		return -1;
	}else if(xn->type != XML_TEXT_NODE){
		return -1;
	}
	if((ictx->shmprefix = Strdup((const char *)xn->content)) == NULL){
		return -1;
	}
	return 0;
}

static int
use_respmod_config(icap_config *ictx,xmlNodePtr xn){
	int ret = 0;

	if((xn = xn->children) == NULL){
		return -1;
	}
	do{
		if(xmlStrcmp(xn->name,(const unsigned char *)XMLTAG_URIPATH) == 0){
			if(xn->children){
				ret |= use_uri(&ictx->respmod_uri,xn->children->content);
			}
		}
		xn = xn->next;
	}while(xn);
	return ret;
}

static int
use_icap_config(icap_config *ictx,xmlNodePtr xn){
	int ret = 0;

	memset(ictx,0,sizeof(*ictx));
	ictx->port = DEFAULT_ICAP_PORT;
	if((xn = xn->children) == NULL){
		bitch("Childless icap_state element\n");
		ret = -1;
	}else do{
		if(xn->type != XML_ELEMENT_NODE){
			continue;
		}
		if(xmlStrcmp(xn->name,(const unsigned char *)"module") == 0){
			ret |= use_module_config(ictx,xn);
		}else if(xmlStrcmp(xn->name,(const unsigned char *)"reqmod") == 0){
			ret |= use_reqmod_config(ictx,xn);
		}else if(xmlStrcmp(xn->name,(const unsigned char *)"respmod") == 0){
			ret |= use_respmod_config(ictx,xn);
		}else if(xmlStrcmp(xn->name,(const unsigned char *)XMLTAG_PORT) == 0){
			ret |= use_port_config(&ictx->port,xn);
		}else if(xmlStrcmp(xn->name,(const unsigned char *)XMLTAG_SHMPREFIX) == 0){
			ret |= use_shm_prefix(ictx,xn);
		}else if(xmlStrcmp(xn->name,(const unsigned char *)XMLTAG_HCONF) == 0){
			if(ictx->handler_api == NULL){
				bitch("Can't specify %s prior to module\n",XMLTAG_HCONF);
				ret = -1;
			}else if(ictx->handler_api->hci == NULL){
				bitch("Can't specify %s with specified module\n",XMLTAG_HCONF);
				ret = -1;
			}else if(ictx->handler_api->hci->hcb == NULL){
				bitch("Can't specify %s with specified module\n",XMLTAG_HCONF);
				ret = -1;
			}else if((ictx->handlerconf = ictx->handler_api->hci->hcb(xn)) == NULL){
				bitch("Error in handler configuration callback\n");
				ret = -1;
			}
			nag("Successful %s callback\n",XMLTAG_HCONF);
		}else{
			bitch("Unknown config directive: %s\n",xn->name);
			ret = -1;
		}
	}while(!ret && (xn = xn->next));
	return ret;
}

static int
use_smtp_config(smtp_config *sctx,xmlNodePtr xn){
	memset(sctx,0,sizeof(*sctx));
	sctx->port = DEFAULT_SMTP_PORT;
	xn = xn->children;
	while(xn){
		if(xn->type == XML_ELEMENT_NODE){
			if(xmlStrcmp(xn->name,(const unsigned char *)XMLTAG_PORT) == 0){
				if(use_port_config(&sctx->port,xn)){
					return -1;
				}
			}else{
				bitch("Unknown config directive: %s\n",xn->name);
				return -1;
			}
		}
		xn = xn->next;
	}
	return 0;
}

static int
use_http_config(http_config *hctx,xmlNodePtr xn){
	memset(hctx,0,sizeof(*hctx));
	hctx->port = DEFAULT_HTTP_PORT;
	xn = xn->children;
	while(xn){
		if(xn->type == XML_ELEMENT_NODE){
			if(xmlStrcmp(xn->name,(const unsigned char *)XMLTAG_PORT) == 0){
				if(use_port_config(&hctx->port,xn)){
					return -1;
				}
			}else{
				bitch("Unknown config directive: %s\n",xn->name);
				return -1;
			}
		}
		xn = xn->next;
	}
	return 0;
}

static int
use_snare_config(const xmlDocPtr xd){
	snare_config tmpconf;
	xmlNodePtr xn;
	int ret = 0;

	if((xn = xmlDocGetRootElement(xd)) == NULL || xmlStrcmp(xn->name,(const unsigned char *)XMLTAG_SNARE)){
		bitch("Didn't get a root " XMLTAG_SNARE "element\n");
		ret = -1;
	}else if((xn = xn->children) == NULL){
		bitch("No children in root " XMLTAG_SNARE "element\n");
		ret = -1;
	}else do{
		if(xn->type != XML_ELEMENT_NODE){
			continue;
		}
		if(xmlStrcmp(xn->name,(const unsigned char *)XMLTAG_HTTP) == 0){
			ret |= use_http_config(&tmpconf.hctx,xn);
		}else if(xmlStrcmp(xn->name,(const unsigned char *)XMLTAG_SMTP) == 0){
			ret |= use_smtp_config(&tmpconf.sctx,xn);
		}else if(xmlStrcmp(xn->name,(const unsigned char *)XMLTAG_ICAP) == 0){
			ret |= use_icap_config(&tmpconf.ictx,xn);
		}else{
			bitch("Unknown config directive: %s\n",xn->name);
			ret = -1;
		}
	}while(!ret && (xn = xn->next));
	if(ret == 0){
		// FIXME these semantics aren't quite accurate; we'll already
		// have changed up any modules' configuration... hrm
		nag("Resetting configuration\n");
		block_all_pollers();
		free_snare_config(&conf);
		conf = tmpconf;
		unblock_all_pollers();
		nag("Reset configuration\n");
	}else{
		free_snare_config(&tmpconf);
	}
	return ret;
}

static int
srv_snare_dump(cmd_state *cs __attribute__ ((unused))){
	int ret = 0;

	block_all_pollers();
	ret |= dump(stringize_snare_config);
	unblock_all_pollers();
	return ret;
}

static command commands[] = {
	{ .cmd = "config_dump",			.func = srv_snare_dump,			},
	{ .cmd = "icap_stats_dump",		.func = srv_icap_stats_dump,		},
	{ .cmd = "icap_stats_clear",		.func = srv_icap_stats_clear,		},
	{ .cmd = NULL,				.func = NULL,				}
};

int init_config(void){
	struct config_data *icap_config_store;
	#define ICAP_CONFIG "snare.conf"
	xmlDocPtr xd;
	int ret;

	if(init_icap_http()){
		return -1;
	}
	if((icap_config_store = open_config(ICAP_CONFIG)) == NULL){
		free_snare_config(&conf);
		stop_icap_http();
		return -1;
	}
	if(parse_config_xmlfile(icap_config_store,&xd)){
		free_config_data(&icap_config_store);
		free_snare_config(&conf);
		stop_icap_http();
		return -1;
	}
	ret = use_snare_config(xd);
	free_config_data(&icap_config_store);
	xmlFreeDoc(xd);
	if(ret){
		free_snare_config(&conf);
		stop_icap_http();
		return -1;
	}
	if(regcommands(commands)){
		free_snare_config(&conf);
		stop_icap_http();
		return -1;
	}
	return 0;
	#undef ICAP_CONFIG
}

static int
stringize_uripath(ustring *u,const char *uri){
	if(printUString(u,"<" XMLTAG_URIPATH ">%s</" XMLTAG_URIPATH ">",uri) < 0){
		return -1;
	}
	return 0;
}

static int
stringize_reqmod_config(ustring *u,const icap_config *ictx){
	#define REQMOD_CONFIG_ELEM "reqmod"
	if(printUString(u,"<"REQMOD_CONFIG_ELEM">") < 0){
		return -1;
	}
	if(stringize_uripath(u,ictx->reqmod_uri)){
		return -1;
	}
	if(printUString(u,"</"REQMOD_CONFIG_ELEM">") < 0){
		return -1;
	}
	return 0;
	#undef REQMOD_CONFIG_ELEM
}

static int
stringize_respmod_config(ustring *u,const icap_config *ictx){
	if(ictx->respmod_uri){
		#define RESPMOD_CONFIG_ELEM "respmod"
		if(printUString(u,"<"RESPMOD_CONFIG_ELEM">") < 0){
			return -1;
		}
		if(stringize_uripath(u,ictx->respmod_uri)){
			return -1;
		}
		if(printUString(u,"</"RESPMOD_CONFIG_ELEM">") < 0){
			return -1;
		}
		#undef RESPMOD_CONFIG_ELEM
	}
	return 0;
}

static int
stringize_port(ustring *u,uint16_t port){
	if(printUString(u,"<" XMLTAG_PORT ">%hu</" XMLTAG_PORT ">",port) < 0){
		return -1;
	}
	return 0;
}

static int
stringize_handler_config(ustring *u,const struct handler_config_interface *hapi,
				const struct handlerconf *hconf){
	if(hapi->scb){
		if(printUString(u,"<" XMLTAG_HCONF ">") < 0){
			return -1;
		}
		if(hapi->scb(u,hconf)){
			return -1;
		}
		if(printUString(u,"</" XMLTAG_HCONF ">") < 0){
			return -1;
		}
	}
	return 0;
}

static int
stringize_shmprefix(ustring *u,const char *shmprefix){
	if(shmprefix){
		if(printUString(u,"<" XMLTAG_SHMPREFIX ">%s</" XMLTAG_SHMPREFIX ">",shmprefix) < 0){
			return -1;
		}
	}
	return 0;
}

static int
stringize_smtp_config(ustring *u,const smtp_config *sctx){
	if(printUString(u,"<" XMLTAG_SMTP ">") < 0){
		return -1;
	}
	if(stringize_port(u,sctx->port)){
		return -1;
	}
	if(printUString(u,"</" XMLTAG_SMTP ">") < 0){
		return -1;
	}
	return 0;
}

static int
stringize_http_config(ustring *u,const http_config *hctx){
	if(printUString(u,"<" XMLTAG_HTTP ">") < 0){
		return -1;
	}
	if(stringize_port(u,hctx->port)){
		return -1;
	}
	if(printUString(u,"</" XMLTAG_HTTP ">") < 0){
		return -1;
	}
	return 0;
}

static int
stringize_icap_config(ustring *u,const icap_config *ictx){
	if(printUString(u,"<" XMLTAG_ICAP ">") < 0){
		return -1;
	}
	if(stringize_port(u,ictx->port)){
		return -1;
	}
	if(stringize_shmprefix(u,ictx->shmprefix)){
		return -1;
	}
	if(stringize_reqmod_config(u,ictx)){
		return -1;
	}
	if(stringize_respmod_config(u,ictx)){
		return -1;
	}
	if(ictx->handler_api && ictx->handler_api->hci){
		if(stringize_handler_config(u,ictx->handler_api->hci,ictx->handlerconf)){
			return -1;
		}
	}
	if(printUString(u,"</" XMLTAG_ICAP ">") < 0){
		return -1;
	}
	return 0;
}

// FIXME all of these constant elements should be redefined in terms of the
// XML parse_entitites structure elements, so they're kept in sync. better yet
// there should be a generic function which walks the tree and prints values
int stringize_snare_config(ustring *u){
	if(printUString(u,"<" XMLTAG_SNARE ">") < 0){
		return -1;
	}
	if(stringize_smtp_config(u,&conf.sctx)){
		return -1;
	}
	if(stringize_http_config(u,&conf.hctx)){
		return -1;
	}
	if(stringize_icap_config(u,&conf.ictx)){
		return -1;
	}
	if(printUString(u,"</" XMLTAG_SNARE ">") < 0){
		return -1;
	}
	return 0;
}

int stop_config(void){
	int ret = 0;

	ret |= delcommands(commands);
	free_snare_config(&conf);
	ret |= stop_icap_http();
	return ret;
}

int is_reqmod_uri(const char *uri){
	return conf.ictx.reqmod_uri && !strcasecmp(uri,conf.ictx.reqmod_uri);
}

int is_respmod_uri(const char *uri){
	return conf.ictx.respmod_uri && !strcasecmp(uri,conf.ictx.respmod_uri);
}

uint16_t icap_port(void){
	return conf.ictx.port;
}

void icap_shmprefix(char path[PATH_MAX]){
	strcpy(path,conf.ictx.shmprefix ? conf.ictx.shmprefix : "");
}

void icap_handler_interface(handler_interface *hapi){
	*hapi = *(conf.ictx.handler_api);
}
