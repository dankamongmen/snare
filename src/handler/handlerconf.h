#ifndef HANDLER_HANDLERCONF
#define HANDLER_HANDLERCONF

#include <snare/modules.h>

void get_handler_conf(char []);

char *get_repper_server(void);
char *get_bontool_path(void);
char *get_bontool_sigs(void);

#define add_conf_uri(tagname, varname) \
	char *get_ ## varname(void); \
	int cmp_ ## varname(const char *); \
	size_t cmpn_ ## varname(const char *);
#include "handlerconf_uris.h"
#undef add_conf_uri

void free_bassdrum_config(struct handlerconf *);
int stringize_bassdrum_config(struct ustring *,const struct handlerconf *);
void set_bassdrum_config(const struct handlerconf *);

void get_hmac_key(void *);
char *get_auth_token_hmac_key(void);
long get_auth_time_window(void);
long get_bypass_time_window(void);
unsigned int get_proxyauth_nonce_diff(void);
const char *get_proxyauth_html(void);
unsigned int get_vid_size(void);
const char *get_generic_pac(void);
int is_allowed_port(uint16_t);
int is_ntlm_excl_ua(const char *);
int is_cookie_excl_ua(const char *);
const char *testuri_lookup(const char *);

#endif
