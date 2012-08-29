#include <stdio.h>
#include <string.h>
#include <libdank/utils/string.h>
#include <libdank/utils/memlimit.h>
#include <libdank/objects/logctx.h>
#include "cookie.h"

CookieNodeType* parse_cookies(const char *cookie_string) {
  return (CookieNodeType*)parse_params(cookie_string, ";,");
}

void delete_cookie_list(CookieNodeType *cookie_list) {
  delete_param_list((ParamNodeType*)cookie_list);
}

void print_cookies(CookieNodeType *cookie_list) {
  print_params((ParamNodeType*)cookie_list);
}

int filter_swps_cookies(CookieNodeType **cookie_list, char **auth, char **user) {
  ParamNodeType *cur, *prev = NULL;
  char *name;
  int delete;
  int modified = 0;

  *auth = *user = NULL;
  
  cur = (ParamNodeType*)*cookie_list;

  while(cur) {
    name = cur->param_value.name;
    while(*name == ' ' || *name == '\t') {
      name++;
    }
    delete = 0;
    if(strcmp(name, AUTH_DOM_COOKIE_TOKEN) == 0) {
      *auth = cur->param_value.value;
      delete = 1;
    } else if(strcmp(name, AUTH_DOM_COOKIE_USER) == 0) {
      *user = cur->param_value.value;
      delete = 1;
    }
    if(delete) {
      modified = 1;
      if(prev) {
	prev->next = cur->next;
	Free(cur->param_value.name);
	Free(cur);
	cur = prev->next;
      } else {
	*cookie_list = (CookieNodeType*)cur->next;
	Free(cur->param_value.name);
	Free(cur);
	cur = (ParamNodeType*)*cookie_list;
      }
    } else {
      prev = cur;
      cur = cur->next;
    }
  }
  return modified;
}

int rebuild_cookie(CookieNodeType *cookie_list, ustring *u) {
  return rebuild_params((ParamNodeType*)cookie_list, u, ";");
}

char* get_cookie_value(CookieNodeType *param_list, const char *name) {
  return get_param_value((ParamNodeType*)param_list, name, 1);
}

int set_cookie_value(CookieNodeType **param_list,  const char *name, const char *value) {
  return set_param_value((ParamNodeType**)param_list, name, value, 1);
}

void delete_cookie(CookieNodeType **param_list, const char *name) {
  delete_param((ParamNodeType**) param_list, name, 1);
}
