#ifndef COOKIE_H
#define COOKIE_H

#include <libdank/objects/objustring.h>
#include "param.h"

#define AUTH_DOM_COOKIE_TOKEN "scur-swps-dom-auth-token"
#define AUTH_DOM_COOKIE_USER "scur-swps-dom-auth-uid"

typedef struct ParamNodeType CookieNodeType;

CookieNodeType* parse_cookies(const char *cookie_string);
void delete_cookie_list(CookieNodeType *cookie_list);
void print_cookies(CookieNodeType *cookie_list);
int filter_swps_cookies(CookieNodeType **cookie_list, char **auth, char **user);
int rebuild_cookie(CookieNodeType *cookie_list, ustring *u);
char* get_cookie_value(CookieNodeType *param_list, const char *name);
int set_cookie_value(CookieNodeType **param_list,  const char *name, const char *value);
void delete_cookie(CookieNodeType **param_list, const char *name);

#endif
