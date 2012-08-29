#include <ctype.h>
#include <libdank/objects/logctx.h>
#include <libdank/objects/objustring.h>
#include <libdank/utils/rfc2396.h>
#include <libdank/utils/string.h>
#include <libdank/utils/memlimit.h>
#include "param.h"
#include "cookie.h"
#include "stringpp.h"
#include "safesearch.h"

#define CAT_SEARCH_ENGINE	145

static int
modify_parameter(char **query, const char *name, const char *value) {
  ParamNodeType *pl = NULL;
  int ret = -1;
  ustring us = USTRING_INITIALIZER;
  char *result;

  pl = parse_params(*query, "&");
  if(!pl) {
    nag("Error parsing query string\n");
    goto cleanup;
  }

  if(set_param_value(&pl, name, value, 0)) {
    nag("Error setting query string value\n");
    goto cleanup;
  }

  if(rebuild_params(pl, &us, "&")) {
    nag("Error rebuilding query string\n");
    goto cleanup;
  }

  result = Strdup(us.string);
  if(!result) {
    goto cleanup;
  }
 
  Free(*query);
  *query = result;

  ret = 0;

 cleanup:
  delete_param_list(pl);
  reset_ustring(&us);
  return ret;
}

static void
process_msn_cookie(const char *cookie, char **new_cookie) {
  CookieNodeType *cl;
  char *cookie_val;
  char *new_cookie_val = NULL;
  char *new2_cookie_val = NULL;
  cl = parse_cookies(cookie);
  if(!cl) {
    nag("Error parsing cookies\n");
  } else {
    cookie_val = get_cookie_value(cl, "SRCHHPGUSR");
    if(!cookie_val) {
      nag("No SRCHHPUSR cookie, cookie is %s\n", cookie);
    } else {
      new_cookie_val = find_and_replace(cookie_val, "&ADLT=OFF&", "&ADLT=STRICT&");
      if(!new_cookie_val) {
	nag("Error replacing string\n");
      } else {
	new2_cookie_val = find_and_replace(new_cookie_val, "&ADLT=DEMOTE&", "&ADLT=STRICT&");
	Free(new_cookie_val);
	if(!new2_cookie_val) {
	  nag("Error replacing string\n");
	} else {
	  if(set_cookie_value(&cl, "SRCHHPGUSR", new2_cookie_val)) {
	    nag("Error setting new cookie value\n");
	  } else {
	    ustring ucookie = USTRING_INITIALIZER;
	    if(rebuild_cookie(cl, &ucookie)) {
	      nag("Error rebuilding cookie\n");
	    } else {
	      *new_cookie = Strdup(ucookie.string);
	    }
	    reset_ustring(&ucookie);
	  }
	  Free(new2_cookie_val);
	}
      }
    }
  }
  delete_cookie_list(cl);
}

static void
process_alltheweb_cookie(const char *cookie, char **new_cookie) {
  CookieNodeType *cl;
  char *cookie_val;
  char *new_cookie_val = NULL;
  
  *new_cookie = NULL;

  cl = parse_cookies(cookie);
  if(!cl) {
    nag("Error parsing cookies\n");
  } else {
    cookie_val = get_cookie_value(cl, "PREF");
    if(!cookie_val) {
      nag("No PREF cookie, cookie is %s\n", cookie);
    } else {
      new_cookie_val = find_and_replace(cookie_val, ":no=off", "");
      if(!new_cookie_val) {
	nag("Error replacing string\n");
      } else {
	if(set_cookie_value(&cl, "PREF", new_cookie_val)) {
	  nag("Error setting new cookie value\n");
	} else {
	  ustring ucookie = USTRING_INITIALIZER;
	  if(rebuild_cookie(cl, &ucookie)) {
	    nag("Error rebuilding cookie\n");
	  } else {
	    *new_cookie = Strdup(ucookie.string);
	  }
	  reset_ustring(&ucookie);
	}
	Free(new_cookie_val);
      }
    }
  }
  delete_cookie_list(cl);
}

static int
process_alltheweb_query(char **query) {
  if(*query && **query) {
    // query exists and is not empty
    if(modify_parameter(query, "ocjp", "1")) {
      nag("Can't modify query string\n");
    } else {
      return 1;
    }
  }
  return 0;
}

static void
process_altavista_cookie(const char *cookie, char **new_cookie) {
  CookieNodeType *cl;
  ustring ucookie = USTRING_INITIALIZER;
  *new_cookie = NULL;

  cl = parse_cookies(cookie);
  if(!cl) {
    nag("Error parsing cookies\n");
    goto cleanup;
  }

  delete_cookie(&cl, "AV_ALL");
  if(set_cookie_value(&cl, " AV_PG", "1")) {
    nag("Error setting new cookie value\n");
    goto cleanup;
  }

  if(rebuild_cookie(cl, &ucookie)) {
    nag("Error rebuilding cookie\n");
    goto cleanup;
  }
  
  *new_cookie = Strdup(ucookie.string);

 cleanup:
  delete_cookie_list(cl);
  reset_ustring(&ucookie);
}

static int
process_altavista_query(char **query) {
  if(*query && **query) {
    // query exists and is not empty
    if(modify_parameter(query, "fft", "1")) {
      nag("Can't modify query string\n");
    } else {
      return 1;
    }
  }
  return 0;
}

static int
process_google_query(char **query) {
  if(strncmp(*query, "q=", 2) == 0 || strstr(*query, "&q=")) {
    if(modify_parameter(query, "safe", "active")) {
      nag("Can't modify query string\n");
    } else {
      return 1;
    }
  }
  return 0;
}

static int
process_yahoo_query(char **query, const char *path) {
  if(strncmp(*query, "p=", 2) == 0
     || strstr(*query, "&p=")
     || (strstr(path, "search") && *query != NULL && (*query)[0] != '\0')) {
    if(modify_parameter(query, "vm", "r")) {
      nag("Can't modify query string\n");
    } else {
      return 1;
    }
  }
  return 0;
}

static int
process_bing_query(char **query) {
  if(strncmp(*query, "q=", 2) == 0 || strstr(*query, "&q=")) {
    if(modify_parameter(query, "adlt", "strict")) {
      nag("Can't modify query string\n");
    } else {
      return 1;
    }
  }
  return 0;
}

static int
is_search_engine(const SiteInfoType *si) {
  int i;
  for(i = 0; i < si->num_cats; i++) {
    if(si->cat_array[i] == CAT_SEARCH_ENGINE) {
      return -1;
    }
  }
  return 0;
}

int modify_url_cookie_for_safe_search(char **url, const char *cookie, char **new_cookie,
				      const SiteInfoType *si) {
  uri *u;
  char *urls, *urls2;
  int is_google = 0, is_yahoo = 0, is_msn = 0, is_alltheweb = 0, is_altavista = 0, is_a9 = 0, is_bing = 0, is_known = 0;
  int url_modified = 0;
  ustring us = USTRING_INITIALIZER;

  if(cookie) {
    if(!new_cookie) {
      bitch("Passed cookie but no pointer for rewritten cookie\n");
      return 0;
    }
    *new_cookie = 0;
  }

  urls = urls2 = Strdup(*url);
  u = extract_uri(0, &urls);
  Free(urls2);
  if(!u) {
    nag("URI extraction failed\n");
    return 0;
  }
  
  if(u->host) {
    if(strcasestr(u->host, "google.") && !strcasestr(u->host, "maps.google.")) {
      is_google = is_known = 1;
    } else if(strcasestr(u->host, "yahoo.")) {
      is_yahoo = is_known = 1;
    } else if(strcasestr(u->host, ".msn.") || strcasestr(u->host, "search.live.")) {
      is_msn = is_known = 1;
    } else if(strcasestr(u->host, "alltheweb.")) {
      is_alltheweb = is_known = 1;
    } else if(strcasestr(u->host, "altavista.")) {
      is_altavista = is_known = 1;
    } else if(strcasestr(u->host, "a9.")) {
      is_a9 = is_known = 1;
    } else if(strcasestr(u->host, ".bing.com")) {
      is_bing = is_known = 1;
    }

    // xxx WW uses some additional heuristics here based on category information and the presence of certain strings in the cookie

    if(!is_known) {
      size_t i;
      int is_ip = 1;
      for(i = 0; i < strlen(u->host); i++) {
	if(isalpha(((const unsigned char *)u->host)[i])) {
	  is_ip = 0;
	  break;
	}
      }
      if(is_ip && u->query && is_search_engine(si)) {
	if(strncmp(u->query, "q=", 2) == 0 || strstr(u->query, "&q=")) {
	  is_google = is_known = 1;
	} else if(strncmp(u->query, "p=", 2) == 0 || strstr(u->query, "&p=")) {
	  is_yahoo = is_known = 1;
	}
      }
    }
  }

  if(is_google && u->query) {
    url_modified = process_google_query(&(u->query));
  } else if(is_yahoo && u->query) {
    url_modified = process_yahoo_query(&(u->query), u->path);
  } else if(is_msn && cookie) {
    process_msn_cookie(cookie, new_cookie);
  } else if(is_alltheweb && cookie) {
    process_alltheweb_cookie(cookie, new_cookie);
    if(new_cookie) {
      url_modified = process_alltheweb_query(&(u->query));
    }
  } else if(is_altavista && cookie) {
    process_altavista_cookie(cookie, new_cookie);
    if(new_cookie) {
      url_modified = process_altavista_query(&(u->query));
    }
  } else if(is_bing && u->query) {
    url_modified = process_bing_query(&(u->query));
  }

  if(url_modified) {
    char *newurl;
    if(stringize_uri(&us,u) < 0) {
      nag("Error stringizing uri\n");
      free_uri(&u);
      return 0;
    }
    newurl = Strdup(us.string);
    reset_ustring(&us);
    if(!newurl) {
      free_uri(&u);
      return 0;
    }
    Free(*url);
    *url = newurl;
    nag("modified URL\n");
  }
  
  free_uri(&u);
  return url_modified;
}
