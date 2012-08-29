#ifndef SAFESEARCH_H
#define SAFESEARCH_H

#include "handler.h"
#include "siteinfo.h"

int modify_url_cookie_for_safe_search(char **url, const char *cookie, char **new_cookie, const SiteInfoType *si);

#endif
