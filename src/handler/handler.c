#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <util/misc.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <util/sfilter.h>
#include <snare/oqueue.h>
#include <snare/modules.h>
#include <libbon/libbon.h>
#include <snare/threads.h>
#include <librep/librep.h>
#include <handler/cookie.h>
#include <snare/verdicts.h>
#include <util/url_escape.h>
#include <handler/handler.h>
#include <handler/respmod.h>
#include <snare/icap/stats.h>
#include <libdank/utils/hex.h>
#include <libdank/utils/fds.h>
#include <policy/policy_shim.h>
#include <snare/icap/request.h>
#include <libdank/utils/time.h>
#include <handler/handlerconf.h>
#include <snare/icap/response.h>
#include <libdank/utils/parse.h>
#include <libdank/utils/string.h>
#include <libdank/utils/syswrap.h>
#include <libdank/utils/threads.h>
#include <libdank/objects/lexers.h>
#include <libdank/utils/memlimit.h>
#include <libdank/objects/lexers.h>
#include <snare/icap/transmogrify.h>
#include <libdank/objects/crlfreader.h>
#include <libdank/modules/tracing/threads.h>
#include <libdank/modules/ctlserver/ctlserver.h>
#include "ntlm.h"
#include "mobclt.h"
#include "stringpp.h"
#include "proxyauth.h"
#include "safesearch.h"
#include "vid_nc_map.h"
#include "util/base64.h"
#include "handler_common.h"

// Timeout period in seconds for librep queries
#define TIMEOUT_SEC 1

// String that the cookie auth page (captive portal) appends to the URL when
// redirecting back to us. We pick up the token and transform the authentication
// data in it into a cookie.
#define AUTH_TOKEN_PREFIX "scur-swps-auth-redirect="

// The ICAP profile string that WW uses when we should use cookie auth instead
// of proxy auth (this is based on the port the client connects to on the
// Webwasher)
#define COOKIE_AUTH_PROFILE_STRING "profile=SWPS-Cookie-Auth"

// The ICAP profile string that WW sends when we should assume a certain eid
#define PORT_EID_PROFILE_STRING "profile=SWPS-Port-EID-"

static time_t last_reconfig;
bassdrum_stats bstats;

static struct rep_network *global_repnet;

static char policy_file[PATH_MAX];
unsigned char internal_hmac_key[HMAC_KEY_LEN];
char *auth_token_hmac_key;	// Needs to match value in ulogin.php
long auth_time_window;
long bypass_time_window;

struct rep_data {
  rep_query *rq;
  uint32_t client_ip;
  char *method,*url,*httpver;
  unsigned int eid;
  unsigned int pid;
  unsigned int uid;
  unsigned int gid;
  int is_blacklisted;
  struct oqueue_key *okey;
  struct timeval dispatch_time;
};

/* whoami Notes begin */
// No authentication
#define AUTH_NONE                0

// A cached cookie from the Web Filter Agent in the X-SWEB-Cookie header
#define AUTH_WFA_SWEB_COOKIE     1

// Using only customer id from WFA and then continue with cookie auth
#define AUTH_WFA_SAML            2

// User data retrieved from WFA headers (normal/common WFA operation)
#define AUTH_WFA_NATIVE          3

// Cookie authentication: Sending user to portal site to log in, redirection back to us
// with auth data, setting a cookie for each visited domain
#define AUTH_COOKIE              4

// Authentication based on IP address
#define AUTH_IP                  5

// IP address range with NTLM enabled -- user data retrieved via NTLM proxy authentication
#define AUTH_IP_NTLM             6

// IP address range with cookie auth enabled -- send users from this IP range to cookie auth page,
// commonly used for SAML
#define AUTH_IP_COOKIE           7

// Workaround for NTLM over IE6, utilizes the cookie auth login page to do the NTLM transaction with the client
#define AUTH_NTLM_IE6            8

// Standard proxy authentication: We request digest, but we accept also basic
#define AUTH_PROXY               9

// Port-based NTLM: We detect the port the client used on our end using a WW profile string and then
// use a customer id based on that to do an NTLM lookup
#define AUTH_PORT_NTLM           10

// Notes on SAML:
// SAML works over the cookie auth page, but we need to know the customer id beforehand so that we
// can send the user to the right SAML IdP.

typedef struct authscheme {
  int type;
  const char * name; 
} authscheme;
// xxx fixme:
/* Sorry, so far, keep the same order as above macro please. */
static const authscheme  authschemes[] = {
  {AUTH_NONE,            "None"},
  {AUTH_WFA_SWEB_COOKIE, "WFA -- SWEB-Cookie"},
  {AUTH_WFA_SAML,        "WFA -- SAML-Cookie"},
  {AUTH_WFA_NATIVE,      "WFA -- native"},
  {AUTH_COOKIE,          "Cookie"},
  {AUTH_IP,              "IP"},
  {AUTH_IP_NTLM,         "IP NTLM"},
  {AUTH_IP_COOKIE,       "IP COOKIE"},
  {AUTH_NTLM_IE6,        "NTLM IE6"},
  {AUTH_PROXY,           "Proxy"},
  {AUTH_PORT_NTLM,       "Port NTLM"},
};
/* whoami Notes end */

static inline void
update_avgmax(avgmax_stats *stats, struct timeval *starttime) {
  intmax_t usec;
  struct timeval tv;
  Gettimeofday(&tv, NULL);
  usec = timeval_subtract_usec(&tv, starttime);
  adjust_avgmax_stats(stats, usec);
}

// Send back a warn (coaching) page. The user needs to click through to get the actual page.
static int
reqresp_warn(struct icap_state *is, const char *url, const char *html, const SiteInfoType *si) {
  if(is_https(is)) {
    char *blockuri;
    nag("Blocking on HTTPS CONNECT\n");
    if((blockuri = get_blockuri())) {
      ustring us = USTRING_INITIALIZER;
      char *bldat = encode_block_page_data(url, si, -1);
      if(!bldat) {
	nag("Error encoding block page data\n");
	Free(blockuri);
	return -1;
      }
      if(printUString(&us, "%s%s", blockuri, bldat) < 0) {
	Free(blockuri);
	Free(bldat);
	return -1;
      }
      reqresp_redirect(is, us.string);
      Free(blockuri);
      Free(bldat);
      reset_ustring(&us);
    } else {
      // No block page URI => send back error page. Well, the client won't see
      // this since it causes the behavior described in Bug 311, but this is
      // better than nothing...
      return reqresp_error(is);
    }
  } else {
        const char *response_hdr = OK_HEADERS;

	ustring urlb = USTRING_INITIALIZER, htmllink = USTRING_INITIALIZER;
	uint8_t hmac[16];
	char hex_hmac[33]; // 2 * 16 characters plus \0
	time_t now = time(0);
	char *html2 = NULL, *html3 = NULL;
	char *escaped_url = NULL;
	const char *rule_name;

	// const char *html can be NULL
	if(!html) {
	  reqresp_error_msg(is, "No warn page configured");
	  goto cleanup;
	}

	if(printUString(&urlb,"%s?%s%lu-", url, BYPASS_TOKEN_PREFIX, (unsigned long)now) < 0){
		goto err;
	}

	if((escaped_url = XssEscapeDup(urlb.string)) == NULL){
		goto err;
	}

	HMAC(EVP_md5(), internal_hmac_key, sizeof(internal_hmac_key),
		  (const unsigned char *)urlb.string, urlb.current, hmac, 0);
	asciitohex(hmac, hex_hmac, EOF, sizeof(hmac));

	if(printUString(&htmllink, "<a href=\"%s%s\">%s%s</a>",
		escaped_url, hex_hmac, escaped_url, hex_hmac) < 0){
		goto err;
	}

	rule_name = get_rule_name(si);
	if((html2 = replace_blockwarn_vars(html, url, si, rule_name)) == NULL) {
	  goto err;
	}

	if((html3 = find_and_replace_all(html2, WARN_PAGE_LINK_VAR, htmllink.string)) == NULL) {
	  goto err;
	}

	if(icap_response_rewrite(is, response_hdr, strlen(response_hdr), html3, strlen(html3))){
	  goto cleanup;
	}
	reset_ustring(&htmllink);
	reset_ustring(&urlb);
	Free(html2);
	Free(html3);
	Free(escaped_url);
	return 0;

  err:
	reqresp_error(is);
  cleanup:
	reset_ustring(&htmllink);
	reset_ustring(&urlb);
	Free(html2);
	Free(html3);
	Free(escaped_url);
	return -1;
  }
  return 0;
}

static int
reqresp_redirect_for_bypass(struct icap_state *, const char *) __attribute__ ((warn_unused_result));

// Warn page functionality: Redirect to url and append a bypass token. The token will allow
// the page to be accessed even though there is a warn action defined for that page by the
// policy.
static int
reqresp_redirect_for_bypass(struct icap_state *is, const char *url) {
  ustring respbody = USTRING_INITIALIZER;
  ustring resphdr = USTRING_INITIALIZER;
  ustring urlb = USTRING_INITIALIZER;
  uint8_t hmac[16];
  char hex_hmac[2 * sizeof(hmac) + 1]; // 2 bytes for each octet plus '\0'
  time_t now = time(0);
  char *escaped_url = NULL;

  if(printUString(&urlb, "%s?%s%lu-", url, BYPASS_TOKEN_PREFIX, (unsigned long)now) < 0){
	  goto err;
  }

  if((escaped_url = XssEscapeDup(urlb.string)) == NULL){
  	goto err;
  }

  HMAC(EVP_md5(), internal_hmac_key, sizeof(internal_hmac_key),
       (const unsigned char *)urlb.string, urlb.current, hmac, 0);
  asciitohex(hmac, hex_hmac, EOF, sizeof(hmac));

  if(printUString(&resphdr,
	   "HTTP/1.1 307 Temporary Redirect" CRLF
	   "Location: %s%s" CRLF
	   SERVER_HEADER HTML_CONTENT_HEADER, urlb.string, hex_hmac) < 0){
	  goto err;
  }

  if(printUString(&respbody,
	   "<html><body><h1>Found</h1>"
	   "<p>This site is available at <a href=\"%s%s\">%s%s</a>.</p>"
	   "</body></html>",
	   escaped_url, hex_hmac,
	   escaped_url, hex_hmac
	   ) < 0){
	  goto err;
  }
  if(response_rewrite(is, &resphdr, respbody.string, respbody.current)){
	goto cleanup;
  }
  reset_ustring(&respbody);
  reset_ustring(&resphdr);
  reset_ustring(&urlb);
  Free(escaped_url);
  return 0;

err:
  reqresp_error(is);
cleanup:
  reset_ustring(&urlb);
  reset_ustring(&resphdr);
  reset_ustring(&respbody);
  Free(escaped_url);
  return -1;
}

// Redirect to captive portal login page (commonly ulogin.php)
// Parameters:
// url: the original URL the user tried to go to; if auth succeeds, we'll redirect
//      there in the step
// nip: numeric IP address
// use_ntlm: ask the login page to not prompt for a password but do NTLM instead by
//           appending a paramter to the final redirection URL; used for the IE6
//           workaround (our regular NTLM scheme does not work with IE6)
// saml_eid: send this eid to the login page; commonly used for SAML so that the login
//           page can redirect to the proper SAML IdP; also needed for IE6 NTLM
static int
reqresp_redirect_for_auth(struct icap_state *is, const char *url, uint32_t nip, int use_ntlm, unsigned int saml_eid) {
  ustring respbody = USTRING_INITIALIZER;
  ustring resphdr = USTRING_INITIALIZER;
  ustring urlb = USTRING_INITIALIZER;
  ustring data = USTRING_INITIALIZER;
  uint8_t hmac[20];
  char hex_hmac[41];
  char *escaped_url = NULL;
  size_t len;
  char *hexed_url = NULL;
  char *login_page_uri;

  if(use_ntlm) {
    login_page_uri = get_ntlm_workaround_uri();
  } else {
    login_page_uri = get_loginuri();
  }

  if(!login_page_uri) {
    bitch("No login page uri (use_ntlm = %d)\n", use_ntlm);
    goto err;
  }

  if(saml_eid) {
    if(printUString(&data, "E%u", saml_eid) < 0){
      goto err;
    }
  }

  if(use_ntlm) {
    if(printUString(&data, "N") < 0){
      goto err;
    }
  }

  if(printUString(&data, "%u-%s", nip, url) < 0){
    goto err;
  }

  HMAC(EVP_sha1(), auth_token_hmac_key, strlen(auth_token_hmac_key),
		  (const unsigned char *)data.string, data.current, hmac, 0);
  asciitohex(hmac, hex_hmac, EOF, sizeof(hmac));

  len = strlen(url);
  hexed_url = Malloc("hexed_url", 2 * len + 1);
  if(!hexed_url) {
    goto err;
  }
  asciitohex(url, hexed_url, EOF, len);

  if(printUString(&urlb, "%s?url=%s&nip=%u&hmac=%s&un=%d&eid=%u", login_page_uri, hexed_url, nip, hex_hmac, use_ntlm, saml_eid) < 0){
	  goto err;
  }

  if((escaped_url = XssEscapeDup(urlb.string)) == NULL){
  	goto err;
  }

  if(printUString(&resphdr,
	   "HTTP/1.1 307 Temporary Redirect" CRLF
	   "Location: %s" CRLF SERVER_HEADER
	   "Content-Type: text/html" CRLF, urlb.string) < 0){
	  goto err;
  }

  if(printUString(&respbody,
	   "<html><body><h1>Found</h1>"
	   "<p>The site to which you are navigating is available at "
	   "<a href=\"%s\">%s</a></p>"
	   "</body></html>",
	   escaped_url,
	   escaped_url
	   ) < 0){
	  goto err;
  }
  if(response_rewrite(is, &resphdr, respbody.string, respbody.current)){
	goto cleanup;
  }
  reset_ustring(&respbody);
  reset_ustring(&resphdr);
  reset_ustring(&urlb);
  reset_ustring(&data);
  Free(login_page_uri);
  Free(escaped_url);
  Free(hexed_url);
  return 0;

err:
  reqresp_error(is);
cleanup:
  reset_ustring(&urlb);
  reset_ustring(&resphdr);
  reset_ustring(&respbody);
  reset_ustring(&data);
  Free(login_page_uri);
  Free(escaped_url);
  Free(hexed_url);
  return -1;
}


// Take data that ulogin.php provided in auth token appended to URL and redirect
// user to set the auth data in that token in a cookie for the domain the user
// accessed
static int
reqresp_redirect_auth_token_to_cookie(struct icap_state *is, const char *redir_url, uint32_t nip, unsigned long uid, long ts) {
  ustring respbody = USTRING_INITIALIZER;
  ustring resphdr = USTRING_INITIALIZER;
  ustring id = USTRING_INITIALIZER;
  uint8_t hmac[20];
  char hex_hmac[41];
  char *escaped_url = NULL;

  if((escaped_url = XssEscapeDup(redir_url)) == NULL){
    goto err;
  }

  if(printUString(&id, "c%lu$%ld$%u", uid, ts, nip) < 0) {
    goto err;
  }

  HMAC(EVP_sha1(), internal_hmac_key, sizeof(internal_hmac_key),
		  (const unsigned char *)id.string, id.current, hmac, 0);
  asciitohex(hmac, hex_hmac, EOF, sizeof(hmac));

  if(printUString(&resphdr,
	   "HTTP/1.1 307 Temporary Redirect" CRLF
	   "Location: %s" AUTH_DOM_COOKIE_CHECK_SUFFIX CRLF
	   SERVER_HEADER
	   "Set-Cookie: " AUTH_DOM_COOKIE_TOKEN "=%ld-%s; path=/" CRLF
	   "Set-Cookie: " AUTH_DOM_COOKIE_USER "=c%lu; path=/" CRLF
	   "Content-Type: text/html"CRLF, redir_url, ts, hex_hmac, uid) < 0){
	  goto err;
  }

  if(printUString(&respbody,
	   "<html><body><h1>Found</h1>"
	   "<p>The site to which you are navigating is available at "
	   "<a href=\"%s%s\">%s%s</a></p>"
	   "</body></html>",
	   escaped_url,
	   AUTH_DOM_COOKIE_CHECK_SUFFIX,
	   escaped_url,
	   AUTH_DOM_COOKIE_CHECK_SUFFIX
	   ) < 0){
	  goto err;
  }
  if(response_rewrite(is, &resphdr, respbody.string, respbody.current)){
	  goto cleanup;
  }

  Free(escaped_url);
  reset_ustring(&respbody);
  reset_ustring(&resphdr);
  reset_ustring(&id);

  return 0;

err:
  reqresp_error(is);
cleanup:
  Free(escaped_url);
  reset_ustring(&respbody);
  reset_ustring(&resphdr);
  reset_ustring(&id);
  return -1;
}

// Send back a "not authorized" page
static int
reqresp_noauth(struct icap_state *is, uint32_t nip) {
	ustring respbody = USTRING_INITIALIZER;
	const char *response_hdr = OK_HEADERS;
	char sip[INET_ADDRSTRLEN];
	
	nip = htonl(nip);
	if(!inet_ntop(AF_INET, &nip, sip, sizeof(sip))) {
	  goto err;
	}

	if(printUString(&respbody,
	   "<html><body><h1>Not authorized</h1><p>You are not authorized to use this service. Your IP address is %s.</p></body></html>",
	   sip) < 0){
		goto err;
	}
	if(icap_response_rewrite(is, response_hdr, strlen(response_hdr), respbody.string, respbody.current)){
		goto cleanup;
	}
	reset_ustring(&respbody);
	return 0;

err:
	reqresp_error(is);
cleanup:
	reset_ustring(&respbody);
	return -1;
}

// Send back a "not authorized" page using an HTTP error code. Requested by Pareto
// networks so that their code can detect this condition. The disadvantage of using
// an error code is that IE will replace our HTLM with a "friendly" error page that
// contains no useful information.
static int
reqresp_noauth_403(struct icap_state *is) {
	const char *response_hdr = FORBIDDEN_HEADERS;
	const char *respbody =
	  "<html><body><h1>Forbidden</h1>"
	  "<p>You are not authorized to use this service.</p></body></html>";
	
	if(icap_response_rewrite(is, response_hdr, strlen(response_hdr), respbody, strlen(respbody))){
	  return -1;
	}
	return 0;
}

static int
reqresp_redirect_for_proxy_auth(struct icap_state *is, uint32_t nip, const unsigned char *secret,
				unsigned int vid, int stale) {
  ustring response_hdr = USTRING_INITIALIZER;
  const char *response_body ;
  char *authhdr;

  response_body = get_proxyauth_html();
  
  authhdr = gen_authenticate_hdr(nip, secret, vid, stale);
  if(!authhdr) {
    goto err;
  }

  if(printUString(&response_hdr,
		  "HTTP/1.1 407 Proxy Authentication Required" CRLF
		  SERVER_HEADER HTML_CONTENT_HEADER
		  "%s" CRLF, authhdr) < 0) {
    goto err;
  }
  if(add_icap_respheader(is, "X-ICAP-RESPMOD-Profile: NoRESPMOD")){
    goto cleanup;
  }
  if(response_rewrite(is, &response_hdr, response_body, strlen(response_body))){
    goto cleanup;
  }
  Free(authhdr);
  reset_ustring(&response_hdr);
  return 0;
  
err:
  reqresp_error(is);
cleanup:
  reset_ustring(&response_hdr);
  Free(authhdr);
  return -1;
}

// Respond with the PAC file passed in data
static int
reqresp_pacfile(struct icap_state *is, const char *data) {
  const char *response_hdr = OK_HEADERS_PAC;

  return icap_response_rewrite(is, response_hdr, strlen(response_hdr), data, strlen(data));
}

// Send back a generic PAC file pointing the browser to us
static int
reqresp_generic_pacfile(struct icap_state *is) {
  return reqresp_pacfile(is, get_generic_pac());
}

static int
check_for_generic_pac(icap_state *is, const char *requri, verdict *v) {
  if(cmp_pacuri(requri) || cmp_pacuri2(requri)) {
    // If the request was for a pac file, send a generic one back
    nag("Sending generic PAC\n");
    *v = reqresp_generic_pacfile(is) ? VERDICT_ERROR : VERDICT_DONE;
    return -1;
  }
  return 0;
}

// Send back the "Who-Am-I" page
static int
reqresp_whoami(struct icap_state *is, unsigned int eid, unsigned int gid, unsigned int uid, unsigned int pid, uint32_t ip, int using_ip_auth, int authtype) {
  const char *response_hdr = OK_HEADERS;
  const char *page = HTML_4_01_TRANSITIONAL
    "<html><head><title>Authentication Information Page</title></head>"
    "<body><table>"
    "<tr><td><b>IP Address:</b></td><td>%s</td></tr>"
    "<tr><td><b>Company:</b></td><td>%u</td></tr>"
    "<tr><td><b>Group:</b></td><td>%u</td></tr>"
    "<tr><td><b>User:</b></td><td>%s (%u)</td></tr>"
    "<tr><td><b>Policy:</b></td><td>%u</td></tr>"
    "<tr><td><b>Auth Scheme Used:</b></td><td>%s</td></tr>"
    "<tr><td><b>User Agent:</b></td><td>%s</td></tr>"
    "</table></body></html>";
  char *data = NULL, *username = NULL, *escua = NULL;
  char szIP[INET_ADDRSTRLEN];
  size_t len;
  uint32_t nip;
  int ret = -1;

  nip = htonl(ip);
  if(inet_ntop(AF_INET, &nip, szIP, sizeof(szIP)) == NULL) {
    goto cleanup;
  }

  if(using_ip_auth) {
    username = ec_get_netblock_for_ip(ec, ip);
  } else {
    username = ec_get_user_for_uid(ec, uid);
  }
  if(username == NULL) {
    goto cleanup;
  }

  if(is->encaps.http.user_agent) {
    escua = XssEscapeDup(is->encaps.http.user_agent);
  } else {
    escua = Strdup("<i>null</i>");
  }
  if(!escua) {
    goto cleanup;
  }

  len = strlen(username) + strlen(page) + sizeof(szIP) + sizeof(authschemes[authtype].name) + strlen(escua) + 100;
  data = Malloc("whoami_page", len+1);
  if(data == NULL) {
    goto cleanup;
  }

  if(snprintf(data, len, page, szIP, eid, gid, username, uid, pid, authschemes[authtype].name, escua) >= (int)len) {
    goto cleanup;
  }

  ret = icap_response_rewrite(is, response_hdr, strlen(response_hdr), data, strlen(data));
  
 cleanup:
  Free(username);
  Free(data);
  Free(escua);
  return ret;
} 

int check_auth_cookie(char *c_auth, char *c_user, uint32_t client_ip, time_t now, long auth_time_win) {
  char *s_ts, *s_hmac, *ep;
  long ts;
  uint8_t hmac_buf[SHA_DIGEST_LENGTH], hmac_buf_ref[SHA_DIGEST_LENGTH];
  ustring id = USTRING_INITIALIZER;

  if(!c_auth || !c_user) {
    return 0;
  }

  s_ts = strsep(&c_auth, "-");
  if(!s_ts) {
    return 0;
  }
  if((s_hmac = c_auth) == NULL){
    return 0;
  }

  ts = strtol(s_ts, &ep, 10);
  if((ts == 0 || ts == LONG_MAX || ts == LONG_MIN) && (errno || ep == s_ts)){
    nag("Couldn't convert string at %s\n", s_ts);
    return 0;
  }
  if(*ep){
    nag("Invalid data followed %ld: %s\n", ts, ep);
    return 0;
  }

  // check timestamp
  if(labs(now - ts) > auth_time_win) {
    nag("Auth cookie expired\n");
    return 0;
  }

  if(strlen(s_hmac) < 40) {
    nag("HMAC in auth cookie too short\n");
    return 0;
  }

  if(!hextoascii(s_hmac, hmac_buf, EOF, SHA_DIGEST_LENGTH)) {
    nag("HMAC truncated\n");
    return 0;
  }

  if(printUString(&id, "%s$%ld$%u", c_user, ts, client_ip) < 0) {
    return 0;
  }

  HMAC(EVP_sha1(), internal_hmac_key, sizeof(internal_hmac_key),
       (const unsigned char *)id.string, id.current, hmac_buf_ref, NULL);

  reset_ustring(&id);
  if(memcmp(hmac_buf, hmac_buf_ref, SHA_DIGEST_LENGTH)) {
    // hmac is incorrect
    nag("HMAC doesn't match\n");
    return 0;
  }
  return 1;
}

int check_auth_token(const char *str, char **ret, uint32_t client_ip, unsigned int *uid, long *ts, time_t now) {
  /* Checks for valid token, returns URL w/o token when one is found and null otherwise */
  char *p, *s, *t, *ep, *su, *sut;
  int start_hmac;
  uint8_t hmac_buf[20], hmac_buf_ref[20];
  unsigned long lip;
  uint32_t nip;
  size_t len;
  unsigned long auid;

  *ret = NULL;
  *uid = 0;
  *ts = 0;

  if(!str) {
    nag("Empty string\n");
    return 0;
  }
  nag("Auth check %s\n", str);

  if((s = Strdup(str)) == NULL){
    /* On error, behave as if the token was invalid/not present */
    return 0;
  }

  p = strstr(s, "?" AUTH_TOKEN_PREFIX);
  if(!p) {
    nag("No token found\n");
    /* no token found */
    Free(s);
    return 0;
  }

  p[0] = '\0';

  p += strlen("?" AUTH_TOKEN_PREFIX);

  /* Get timestamp */
  t = strsep(&p, "-");
  if(!t) {
    nag("No delimiter found (extracting timestamp)\n");
    Free(s);
    return 0;
  }

  // Consider replacing this with parse_uint from libdank's lexers.c --nlb
  errno = 0;
  *ts = strtol(t, &ep, 10);
  if((*ts == 0 || *ts == LONG_MAX || *ts == LONG_MIN) && (errno || ep == t)){
	nag("Couldn't convert string at %s\n",t);
	Free(s);
	return 0;
  }
  if(*ep){
	nag("Invalid data followed %ld: %s\n",*ts,ep);
	Free(s);
	return 0;
  }

  /* Get IP */
  t = strsep(&p, "-");
  if(!t) {
    nag("No delimiter found (extracting IP)\n");
    Free(s);
    return 0;
  }
  errno = 0;
  lip = strtoul(t, &ep, 10);
  if((lip == 0 || lip == ULONG_MAX) && (errno || ep == t)){
	nag("Couldn't convert string at %s\n",t);
	Free(s);
	return 0;
  }
  if(*ep){
	nag("Invalid data followed %lu: %s\n",lip,ep);
	Free(s);
	return 0;
  }
  if(lip > 0xffffffff) {
    nag("IP address out of range\n");
    Free(s);
    return 0;
  }
  nip = (uint32_t)lip;

  if(nip != client_ip) {
    Free(s);
    bitch("Client IP in auth token does not match client IP in request (%u, %u)\n", nip, client_ip);
    return 0;
  }

  // Get user id
  t = strsep(&p, "-");
  if(!t) {
    nag("No delimiter found (extracting user)\n");
    Free(s);
    return 0;
  }
  errno = 0;
  auid = strtoul(t, &ep, 10);
  if((auid == ULONG_MAX && errno) || ep == t){
	nag("Couldn't convert string at %s\n",t);
	Free(s);
	return 0;
  }
  if(*ep){
	nag("Invalid data followed %lu: %s\n",auid,ep);
	Free(s);
	return 0;
  }
  if(auid > UINT_MAX) {
    nag("Uid too large\n");
    Free(s);
    return 0;
  }
  *uid = (unsigned int)auid;

  if(p == NULL){
	  nag("Missing delimiter between uid and HMAC\n");
	  Free(s);
	  return 0;
  }
  start_hmac = p - s;
  if(strlen(str) < 40) { // Need 40 bytes, ignore extra stuff at the end
    nag("Length mismatch\n");
    /* This could be an accidentally truncated token. Remove it so that we can rewrite it back to the original URL. */
    *ret = s;
    return 0;
  }

  if(labs(now - *ts) > auth_time_window) {
    nag("Expired timestamp\n");
    /* Remove the expired token since we're going to prompt a new warning page with a new token. */
    *ret = s;
    return 0;
  }

  if(!hextoascii(str + start_hmac, hmac_buf, EOF, 20)) {
    bitch("HMAC truncated\n");
    *ret = s;
    return 0;
  }

  // To calculate the HMAC, we need to operate on the unecaped string (this is
  // what ulogin.php uses now to calculate it)
  // need another one for unescaped version
  if((su = Strdup(str)) == NULL){
    Free(s);
    return 0;
  }
  SFUT_RFC1738Unescape(su, &len);
  if((sut = Strdup(su)) == NULL){
    Free(su);
    Free(s);
    return 0;
  }
  if((p = strstr(sut, "?" AUTH_TOKEN_PREFIX)) == NULL){ // find token start
	bitch("Unescaping invalidated the string\n");
	Free(su);
	Free(s);
	return 0;
  }
  if(p == NULL){
	bitch("Unescaping invalidated the string\n");
	Free(su);
	Free(s);
	return 0;
  }
  p += strlen("?" AUTH_TOKEN_PREFIX);		// skip it
  t = strsep(&p, "-");				// skip timestamp
  t = strsep(&p, "-");				// skip IP
  t = strsep(&p, "-");				// skip user id
  if(p == NULL){
	bitch("Unescaping invalidated the string\n");
	Free(su);
	Free(s);
	return 0;
  }
  start_hmac = p - sut;

  nag("HMAC calc for [%s]/%u %c\n", su, start_hmac, su[start_hmac]);

  HMAC(EVP_sha1(), auth_token_hmac_key, strlen(auth_token_hmac_key),
		  (const unsigned char *)su, start_hmac, hmac_buf_ref, 0);

  Free(su);
  Free(sut);

  *ret = s;
  if(memcmp(hmac_buf, hmac_buf_ref, 20)) {
    // hmac is incorrect
    bitch("HMAC doesn't match\n");
    return 0;
  }

  return 1;
}

// Check if the bypass token (used for warn page/coaching mechanism) is valid.
// str: A URL to check for a bypass token
// ret: If successful, a pointer to a URL w/o the token is returned in this
//      parameter. Needs to be Free()ed.
// return value: 1: token was valid, 0: invalid token or error
int check_bypass_token(const char *str, char **ret) {
  /* Checks for valid token, returns URL w/o token when one is found and null otherwise */
  char *p, *s, *t, *ep;
  long ts;
  time_t now;
  int start_hmac, total_length;
  uint8_t hmac_buf[16], hmac_buf_ref[16];

  *ret = NULL;

  if(!str) {
    nag("Empty string\n");
    return 0;
  }
  nag("Bypass check %s\n", str);

  /* Let's copy this for now... Not sure if modifying the original string is ok */
  if((s = Strdup(str)) == NULL){
    /* On error, let's behave as if the token was invalid/not present for now */
    return 0;
  }

  p = strstr(s, "?" BYPASS_TOKEN_PREFIX);
  if(!p) {
    nag("No token found\n");
    /* no token found */
    Free(s);
    return 0;
  }

  p[0] = '\0';

  p += strlen("?" BYPASS_TOKEN_PREFIX);

  /* Get timestamp */
  t = strsep(&p, "-");
  if(!t) {
    /* delimiter not found */
    nag("No delimiter found\n");
    Free(s);
    return 0;
  }

  // Consider replacing this with parse_uint from libdank's lexers.c --nlb
  errno = 0;
  ts = strtol(t, &ep, 10);
  if((ts == 0 || ts == LONG_MAX || ts == LONG_MIN) && (errno || ep == t)){
	nag("Couldn't convert string at %s\n",t);
	Free(s);
	return 0;
  }
  if(*ep){
	nag("Invalid data followed %ld: %s\n",ts,ep);
	Free(s);
	return 0;
  }

  start_hmac = p - s;
  total_length = strlen(str);
  if(total_length - start_hmac < 32) { // Need 32 bytes, ignore extra stuff at the end, e.g. \r bytes at the end of the referrer
    nag("Length mismatch\n");
    /* This could be an accidentally truncated token. Remove it so that we can rewrite it back to the original URL. */
    *ret = s;
    return 0;
  }

  now = time(0);
  if(labs(now - ts) > bypass_time_window) {
    nag("Expired timestamp\n");
    /* Remove the expired token since we're going to prompt a new warning page with a new token. */
    *ret = s;
    return 0;
  }

  if(!hextoascii(str + start_hmac, hmac_buf, EOF, 16)) {
    bitch("HMAC truncated\n");
    *ret = s;
    return 0;
  }

  HMAC(EVP_md5(), internal_hmac_key, sizeof(internal_hmac_key),
		  (const unsigned char *)str, start_hmac, hmac_buf_ref, 0);
  if(memcmp(hmac_buf, hmac_buf_ref, 16)) {
    // hmac is incorrect
    bitch("HMAC doesn't match\n");
    *ret = s;
    return 0;
  }

  *ret = s;
  return 1;
}

static int modify_for_safesearch(icap_state *is, char **url, const struct rep_data *rd,
				 const SiteInfoType *si) {
  char *new_cookie = NULL;
  int url_changed;

  // xxx Q'n'd workaround for Bug 471 and SafeSearch (user auth for POSTs is still broken)
  //  if(strcmp(is->encaps.http.method, "GET")) {
  //  return 0;
  //}

  url_changed = modify_url_cookie_for_safe_search(url, is->encaps.http.cookie, &new_cookie, si);

  if(new_cookie) {
    nag("Changing cookie for SafeSearch to %s\n", new_cookie);
    if(is->encaps.http.cookie) {
      nag("Old cookie was %s\n", is->encaps.http.cookie);
    }
    if(rewrite_icap_http_header(is, "Cookie:", new_cookie)){
    	Free(new_cookie);
	return -1;
    }
    Free(new_cookie);
  }
  
  if(url_changed) {
    nag("Changing URL for SafeSearch to %s\n", *url);
    if(rewrite_icap_http_startline_flaturi(is, rd->method, *url, rd->httpver)) {
      return -1;
    }
  }
  return 0;
}

static int
warn_action(icap_state *is, struct rep_data *rd, ustring *xattr,
	    int force_safe_search, const SiteInfoType *si) {
  char *returl = NULL;
  char *returl2 = NULL;
  int token_in_referrer = 0;
  int ret = -1;

  // If a warn is received for a POST, we block it instead of showing a
  // warning page (see bug 73)
  if(!strcasecmp("POST", rd->method)) {
    nag("block (POST to warn page)\n");
    if(printUString(xattr, "; action: block; detail: post-to-warn") < 0) {
      goto cleanup;
    }
    reqresp_blocked_by_rule(is, ec_get_block_page(ec, rd->pid), rd->url, si);
    ret = 0;
    goto cleanup;
  }
  
  nag("warn -- check referrer\n");
  if(check_bypass_token(is->encaps.http.referrer, &returl2)) {
    token_in_referrer = 1;
    nag("valid token in referrer\n");
  }
  
  // Not a POST: proceed with warn page logic
  nag("warn -- check url\n");
  if(check_bypass_token(rd->url, &returl)) {
    if(printUString(xattr, "; action: warn detail: bypass") < 0) {
      goto cleanup;
    }
    nag("Found valid token in URL\n");
    if(token_in_referrer) {
      nag("Removing token in referrer\n");
      if(rewrite_icap_http_header(is, "Referer:", returl2)){
        goto cleanup;
      }
    } else {
      nag("No token in referrer, keeping it\n");
    }
    if(force_safe_search) {
      char *new_cookie = NULL;

      if(modify_url_cookie_for_safe_search(&returl, is->encaps.http.cookie, &new_cookie, si)) {
	nag("URL changed for SafeSearch to %s\n", returl);
      }
      if(new_cookie) {
	nag("Cookie changed for SafeSearch to %s\n", new_cookie);
	if(rewrite_icap_http_header(is, "Cookie:", new_cookie)){
          Free(new_cookie);
	  goto cleanup;
	}
      }
      Free(new_cookie);
    }
    /* Redirect request to returl, which does not contain the token */
    if(rewrite_icap_http_startline_flaturi(is, rd->method, returl, rd->httpver)) {
      goto cleanup;
    }
  } else {
    nag("warn -- processing referrer (%s)\n", is->encaps.http.referrer);
    if(token_in_referrer) {
      if(printUString(xattr, "; action: warn detail: redirect") < 0) {
	goto cleanup;
      }
      nag("Found valid token in Referrer\n");
      /* Redirecting to a new page with a valid token */
      if(reqresp_redirect_for_bypass(is, rd->url)){
        goto cleanup;
      }
    } else {
      nag("warn -- prompting\n");
      if(printUString(xattr, "; action: warn detail: prompt") < 0) {
	goto cleanup;
      }
      if(returl) {
	/* If we got a reurl from the first check, redirect to it. This
	   happens when a token has been found but was invalid -- it needs
	   to be removed since otherwise the next warnpage will just append
             a new token after the invalid one. */
	if(reqresp_warn(is, returl, ec_get_warn_page(ec, rd->pid), si)){
	  goto cleanup;
	}
      } else {
	if(reqresp_warn(is, rd->url, ec_get_warn_page(ec, rd->pid), si)){
	  goto cleanup;
	}
      }
    }
  }

  ret = 0;
  
 cleanup:
  Free(returl2);
  Free(returl);
  return ret;
}

// Extracts information from rep_response and fills in predicate objects, which is used by the
// policy module. Also returns data in si (reputation, category information). Si contains pointers
// to data in rr and is therefore not valid anymore once rr has been freed.
//
// Category and rep data from rr is also added to the x-attribute string. 
//
// Si and pr hold essentially the same data in different representation... That should be fixed.
//
// Returns -1 on error.
static int
populate_predicate(const rep_response *rr, struct Predicate *pr, const icap_state *is, struct rep_data *rd, SiteInfoType *si, ustring *xattr) {
  pred_set_hdrs(pr, is); // Copy header fields from icap_state into header map

  if(rd != NULL && rd->uid != 0) {
    pred_set_uid(pr, rd->uid);
  }

  if(rr == NULL){
    bitch("NULL represponse\n");
    //printUString(xattr, "; action: error; detail: repper_comm");
    //return -1;
    return 0; // fail open
  }
  if(rr->has_pr_urlrep && rr->num_pr_urlrep == 1) {
    if(printUString(xattr, "; rep: %d", rr->pr_urlrep[0]) < 0) {
      return -1;
    }
    si->rep = rr->pr_urlrep[0];
  } else {
    si->rep = 0; // Standard rep to use (we should always get one from librep though)
  }
  pred_set_rep(pr, si->rep);
  if(rr->has_pr_urlcats && rr->num_pr_urlcats == 1) {
    int i;
    if(printUString(xattr, "; cat:") < 0) {
      return -1;
    }
    si->num_cats = rr->pr_urlcats_numcats[0];
    si->cat_array = rr->pr_urlcats_catset[0];
    for(i = 0; i < si->num_cats; i++) {
      if(printUString(xattr, " %u", si->cat_array[i]) < 0) {
        return -1;
      }
      pred_add_cat(pr, si->cat_array[i]);
    }
  }
  return 0;
}

static int
add_respmod_poldata(icap_state *is, unsigned int eid, unsigned int pid,
		    unsigned int uid, unsigned int gid, SiteInfoType *si) {
  // Add the policy id to the ICAP header data for the RESPMOD stage
  int ret = -1;
  char *enc = NULL;
  char *bldata = NULL;
  ustring data = USTRING_INITIALIZER;

  // Transmit data from REQMOD to RESMOD by adding a custom HTTP header. The
  // Web server at the other end will unfortunately see it (hence encryption),
  // but this is the only way we can reliably get policy state across. These
  // pieces are transmitted:
  //
  // eid, pid, uid, gid:
  // The policy information derived during authentication in REQMOD.
  //
  // bldata:
  // Originally, this data was used to be able to construct a block page in
  // RESPMOD for malware detections. Since block pages contain category and
  // reputation information, which require a librep lookup, we transmit the
  // data this way.
  // Now that we also evaluate rules in RESPMOD (the ones that require us to
  // look at response headers), this data is also used for that aspect.
  // Therefore, the term "block page data" is misleading under this new model.

  bldata = encode_block_page_data("-", si, 0);
  if(!bldata) {
    nag("Error encoding page meta data\n");
    goto cleanup;
  }
  if(printUString(&data, "pid=%u&bldata=%s&eid=%u&uid=%u&gid=%u", pid, bldata, eid, uid, gid) < 0) {
    goto cleanup;
  }
  enc = encrypt_data((const void*)poldata_key, strlen(poldata_key),
		     (const unsigned char*)data.string, data.current);
  if(!enc) {
    nag("Encryption failed\n");
    goto cleanup;
  }
  if(rewrite_icap_http_header(is, "X-SWEB-Data:", enc)) {
    nag("Adding header failed\n");
    goto cleanup;
  }

  ret = 0;
 cleanup:
  Free(enc);
  Free(bldata);
  reset_ustring(&data);
  return ret;
}

// FIXME break up this function. It's impossible to follow.
static int
rep_callback_internal(const rep_response *rr,int status,struct rep_data *rd,
			icap_state *is,ustring *xattr,struct Predicate *pr){
  ActionType action;
  int ret = -1;
  const char *alert_email_addr = 0;
  int force_safe_search = 0, bypass_anti_malware = 0;
  SiteInfoType si = SITEINFOTYPE_INITIALIZER;
  struct timeval pol_start_time;
  uint32_t flags = 0; // to be passed to RESPMOD

  nag("Handling status %d for rep_data %p pred %p\n",status,rd,pr);
  if(printUString(xattr, "X-Attribute: qid: %lu; eid: %u; uid: %u; gid: %u",
		  qid++, rd->eid, rd->uid, rd->gid) < 0) {
    return -1;
  }

  if(status != eLRNS_OK){
    bitch("rep_callback error %d %p\n",status,rr);
    // printUString(xattr, "; action: error; detail: repper_comm");
    // return -1;
    rr = NULL;
    ++bstats.repper_fail;
  }

  if(populate_predicate(rr, pr, is, rd, &si, xattr)) {
    return -1;
  }

  if(rd->is_blacklisted) {
    si.is_blacklisted = -1;
    if(printUString(xattr, "; action: block; detail: blacklisted") < 0) {
      return -1;
    }
    if(add_icap_respheader(is, xattr->string) < 0) {
      return -1;
    } else {
      reqresp_blocked_by_rule(is, ec_get_block_page(ec, rd->pid), rd->url, &si);
    }
    // xxx this should also be delayed until RESPMOD to allow proper image blocking
    return 0;
  }

  Gettimeofday(&pol_start_time, NULL);
  // Note that this call will also trigger the calculation of some additional
  // data in the predicate, e.g. the quota flag and the time/date information
  action = ec_apply_policy_rules(ec, rd->pid, pr, &alert_email_addr, &si.rule_id, &force_safe_search, &bypass_anti_malware);
  update_avgmax(&bstats.pol_time, &pol_start_time);

  if(bypass_anti_malware) {
    nag("Bypass for anti malware is enabled\n");
    flags |= SWEB_FLAG_WHITELISTED;
  }

  if(alert_email_addr && strlen(alert_email_addr) > 0) {
    if(printUString(xattr, "; alert: %s", alert_email_addr) < 0) {
      return -1;
    }
  }

  switch(action) {
  case ACT_NEED_RESPMOD:
    nag("Rule evaluation delayed till RESPOD\n");
    flags |= SWEB_FLAG_NEED_RESPMOD;
    if(force_safe_search) {
      if(modify_for_safesearch(is, &rd->url, rd, &si)) {
	return -1;
      }
    }
    ret = 0;
    break;
  case ACT_ALLOW:
    if(printUString(xattr, "; action: allow") < 0) {
      return -1;
    }
    if(force_safe_search) {
      if(modify_for_safesearch(is, &rd->url, rd, &si)) {
	return -1;
      }
    }
    ret = 0;
    break;
  case ACT_BLOCK:
    if(is_https(is) || (is->encaps.http.method && strcmp(is->encaps.http.method, "GET"))) {
      // Block here if HTTPS or not a GET request (i.e. don't let POSTs slip out this way)
      if(printUString(xattr, "; action: block") < 0) {
	return -1;
      }
      reqresp_blocked_by_rule(is, ec_get_block_page(ec, rd->pid), rd->url, &si);
    } else {
      // We can block image files with block images in RESPMOD
      nag("Block delayed till RESPOD\n");
      flags |= SWEB_FLAG_NEED_RESPMOD;
      action = ACT_NEED_RESPMOD;
    }
    ret = 0;
    break;
  case ACT_WARN:
    if(warn_action(is, rd, xattr, force_safe_search, &si)) {
      return -1;
    }
    ret = 0;
    break;
  default:
    printUString(xattr, "; action: error");
  }

  if(flags) {
    if(rewritefmt_icap_http_header(is, "X-SWEB-Flags:", "%u", (unsigned)flags)) {
      nag("Adding header failed\n");
      return -1;
    }
  } else {
    if(rewrite_icap_http_header(is, "X-SWEB-Flags:", NULL)) {
      nag("Removing header failed\n");
      return -1;
    }
  }

  if(add_respmod_poldata(is, rd->eid, rd->pid, rd->uid, rd->gid, &si)) {
    return -1;
  }

  if(action != ACT_NEED_RESPMOD) {
    // Don't add an attribute yet -- we need to wait till RESPMOD to determine
    // the action we're going to take
    if(add_icap_respheader(is, xattr->string)){
      ret = -1;
    }
  }
  
  return ret;
}

static void
free_repdata(struct rep_data *rd){
	if(rd){
		repquery_destroy(rd->rq);
		Free(rd->url);
		Free(rd->httpver);
		Free(rd->method);
		Free(rd);
	}
}

static void
rep_callback(rep_response *rr, int status, void *unsafe_rd) {
  struct rep_data *rd = unsafe_rd;
  verdict v = VERDICT_ERROR;
  struct timeval tv;
  oqueue_key *oqk;
  intmax_t usec;

  Gettimeofday(&tv,NULL);
  usec = timeval_subtract_usec(&tv,&rd->dispatch_time);
  adjust_avgmax_stats(&bstats.reppertt,usec);
  oqk = rd->okey;
  if(oqk->cbarg){
    icap_state *is = get_pfd_icap(oqk->cbarg);
    struct Predicate *pr;

    if( (pr = pred_new()) ){
      ustring xattr = USTRING_INITIALIZER;

      if(rep_callback_internal(rr,status,rd,is,&xattr,pr) == 0){
	v = VERDICT_DONE;
      }
      reset_ustring(&xattr);
      pred_delete(pr);
    }
    del_timeout_from_pollqueue(snarepoller,oqk->cbarg->pfd.fd); // FIXME
  }
  oqueue_passverdict_internal(&rd->okey,v);
  free_repdata(rd);
  // nag("Leaving librep handler\n");
}

static int
reprx(struct poller *p __attribute__ ((unused)),pollfd_state *pfd __attribute__ ((unused))){
	int ret;

	// nag("Entering repnet_dispatch\n");
	ret = repnet_dispatch(global_repnet);
	return 0; // we don't want the repper socket destroyed by the poller
	// FIXME or maybe we do, and we should create a thread which tries
	// to create, and add, a new one...hrmm
}

static int
stringize_bassdrum_stats(ustring *u,const bassdrum_stats *bs){
	const struct {
		const char *tag;
		size_t offset;
	} statmap[] = {
		#define BASSDRUM_STAT(stat) \
			{ .tag = #stat, .offset = offsetof(bassdrum_stats,stat), }
		BASSDRUM_STAT(maldetect),
		BASSDRUM_STAT(malclean),
		BASSDRUM_STAT(malerror),
		BASSDRUM_STAT(maljumbo),
		BASSDRUM_STAT(malbypass),
		BASSDRUM_STAT(malbackuptx),
		BASSDRUM_STAT(repper_retries),
		BASSDRUM_STAT(repper_fail),
		BASSDRUM_STAT(uri_error),
		BASSDRUM_STAT(header_error),
		BASSDRUM_STAT(cookie_error),
		BASSDRUM_STAT(ntlm_error),
		BASSDRUM_STAT(auth_error),
		BASSDRUM_STAT(policy_error),
		BASSDRUM_STAT(pac_error),
		BASSDRUM_STAT(auth_wfa_cookie),
		BASSDRUM_STAT(auth_wfa_saml),
		BASSDRUM_STAT(auth_wfa_native),
		BASSDRUM_STAT(auth_ip),
		BASSDRUM_STAT(auth_ip_ntlm),
		BASSDRUM_STAT(auth_ip_ntlm_workaround),
		BASSDRUM_STAT(auth_ip_cookie),
		BASSDRUM_STAT(auth_port_ntlm),
		BASSDRUM_STAT(auth_port_ntlm_ie6),
		BASSDRUM_STAT(auth_proxy),
		BASSDRUM_STAT(auth_cookie),
		BASSDRUM_STAT(auth_none),
		BASSDRUM_STAT(cookie_profile),
		BASSDRUM_STAT(port_profile),
		BASSDRUM_STAT(no_profile),
		BASSDRUM_STAT(vid_size),
		BASSDRUM_STAT(proxyauth_nonce_down),
		{ .tag = NULL, .offset = 0, }
		#undef bassdrum_STAT
	},*cur;

	#define BASSDRUM_STATS_TAG "bassdrum_stats"
	if(printUString(u,"<" BASSDRUM_STATS_TAG ">") < 0){
		return -1;
	}
	for(cur = statmap ; cur->tag ; ++cur){
		if(*(const uintmax_t *)(((const char *)bs) + cur->offset)){
			if(printUString(u,"<%s>%ju</%s>",cur->tag,
				*(const uintmax_t *)(((const char *)bs) + cur->offset),
				cur->tag) < 0){
				return -1;
			}
		}
	}
	if(stringize_curmax_stat(u,"bonblockers",&bstats.bonblocking)){
		return -1;
	}
	if(stringize_avgmax_stat(u,"reppertt",&bstats.reppertt)){
		return -1;
	}
	if(stringize_avgmax_stat(u,"handler_auth_time",&bstats.handler_auth_time)){
		return -1;
	}
	if(stringize_avgmax_stat(u,"pol_time",&bstats.pol_time)){
		return -1;
	}
#define RECONFIG_TAG "config_age"
	if(printUString(u,"<" RECONFIG_TAG ">%.0f</" RECONFIG_TAG ">",
				difftime(time(NULL),last_reconfig)) < 0){
		return -1;
	}
#undef RECONFIG_TAG
	if(stringize_antimalware_version(u)){
		return -1;
	}
	if(printUString(u,"</" BASSDRUM_STATS_TAG ">") < 0){
		return -1;
	}
	#undef BASSDRUM_STATS_TAG
	return 0;
}

static int
stringize_bassdrum_stats_wrapper(ustring *u){
	return stringize_bassdrum_stats(u,&bstats);
}

static int
event_reprx(struct poller *p,pollfd_state *pfd){
	nag("Got an event callback on repper fd %d\n",pfd->pfd.fd);
	return reprx(p,pfd);
}

static int
timeout_reprx(struct poller *p,pollfd_state *pfd){
	if(pfd){
		nag("Got a timeout on repper fd %d\n",pfd->pfd.fd);
		++bstats.repper_retries;
		return reprx(p,pfd);
	}
	nag("Dead session timed out\n"); // should we really be getting these?
	return 0;
}

static void rep_log(void* log_data __attribute__ ((unused)), const char* fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vflog(fmt, ap);
    va_end(ap);
}

static int
polrdr_reload_file(void) {
	struct EntityContainer *tmpec,*newec;

	if((newec = ec_new()) == NULL){
		return 1;
	}
	if(ec_load_policy_file(newec,policy_file)){
		ec_delete(newec);
		return 1;
	}
	block_poller(snarepoller);
	last_reconfig = time(NULL);
	invalidate_istag();
	tmpec = ec;
	ec = newec;
	unblock_poller(snarepoller);
	ec_delete(tmpec);
	return 0;
}

static int
polrdr_reload_file_wrapper(cmd_state *cs __attribute__ ((unused))){
	return polrdr_reload_file();
}

static int
srv_bassdrum_stats_dump(cmd_state *cs __attribute__ ((unused))){
	int ret = 0;

	block_poller(snarepoller);
	ret |= dump(stringize_bassdrum_stats_wrapper);
	unblock_poller(snarepoller);
	return ret;
}

static int
srv_bassdrum_stats_clear(cmd_state *cs __attribute__ ((unused))){
	int ret = 0;

	block_poller(snarepoller);
	memset(&bstats,0,sizeof(bstats));
	unblock_poller(snarepoller);
	return ret;
}

static command commands[] = {
	{ "antimalware_update",		antimalware_update_wrapper,	},
	{ "bassdrum_reconfig",		polrdr_reload_file_wrapper,	},
	{ "bassdrum_stats_dump",	srv_bassdrum_stats_dump,	},
	{ "bassdrum_stats_clear",	srv_bassdrum_stats_clear,	},
	{ NULL,				NULL,				}
};

static unsigned handler_initialized,handler_closing;
static pthread_mutex_t handlerlock = PTHREAD_MUTEX_INITIALIZER;

static int
stringize_librep_fdstate(ustring *u,const struct pollfd_state *pfd){
	if(printUString(u,"<librep>") < 0){
		return -1;
	}
	if(stringize_sdbuf_sizes(u,pfd->pfd.fd)){
		return -1;
	}
	if(printUString(u,"</librep>") < 0){
		return -1;
	}
	return 0;
}

int rep_init(void){
  struct pollfd_submission pfdsub;
  char *repper_host;

  qid = 0;

  set_vid_size(get_vid_size());
  nag("Using vid_size %u\n", get_vid_size());

  get_hmac_key(internal_hmac_key);

  auth_token_hmac_key = get_auth_token_hmac_key();
  if(!auth_token_hmac_key) {
    bitch("No auth_token_hmac_key in configuration file\n");
    return -1;
  }
  auth_time_window = get_auth_time_window();
  bypass_time_window = get_bypass_time_window();

  if(sfilter_init()){
    return -1;
  }

  if(init_ntlm_handling()){
    sfilter_destroy();
    return -1;
  }

  mobclt_init();

  repper_host = get_repper_server();

  // librep-related initializations
  nag("Using repper server at %s\n", repper_host);
  global_repnet = repnet_init(0, TIMEOUT_SEC, repper_host, rep_callback);
  Free(repper_host);
  if(!global_repnet) {
    stop_ntlm_handling();
    sfilter_destroy();
    Free(auth_token_hmac_key);
    return -1;
  }
  repnet_set_logfunc(global_repnet, 0, rep_log);
  if(repnet_connect(global_repnet) != eLR_OK) {
    repnet_destroy(global_repnet);
    stop_ntlm_handling();
    sfilter_destroy();
    Free(auth_token_hmac_key);
    return -1;
  }

  memset(&pfdsub,0,sizeof(pfdsub));
  if((pfdsub.fd = repnet_getsock(global_repnet)) < 0){
    repnet_destroy(global_repnet);
    stop_ntlm_handling();
    sfilter_destroy();
    Free(auth_token_hmac_key);
    return -1;
  }
  if(set_fd_nonblocking(pfdsub.fd) || set_fd_close_on_exec(pfdsub.fd)){
    Close(pfdsub.fd);
    repnet_destroy(global_repnet);
    stop_ntlm_handling();
    sfilter_destroy();
    return -1;
  }
  pfdsub.rxfxn = event_reprx;
  pfdsub.state = global_repnet;
  pfdsub.strfxn = stringize_librep_fdstate;
  // FIXME set address based off repnet lookup
  nag("Adding fd %d to poller\n",pfdsub.fd);
  if(add_fd_to_pollqueue(snarepoller,&pfdsub,NULL,0)){
    repnet_destroy(global_repnet);
    stop_ntlm_handling();
    sfilter_destroy();
    Free(auth_token_hmac_key);
    return -1;
  }

  get_handler_conf(policy_file);
  nag("Using policy file \"%s\"\n", policy_file);

  // policy module
  if(!(ec = ec_new())) {
    repnet_destroy(global_repnet);
    stop_ntlm_handling();
    sfilter_destroy();
    Free(auth_token_hmac_key);
    return -1;
  }

  nag("Reloading policy file\n");

  if(polrdr_reload_file()){
        ec_delete(ec);
        repnet_destroy(global_repnet);
        stop_ntlm_handling();
        sfilter_destroy();
        Free(auth_token_hmac_key);
        return -1;
  }

  nag("Initializing RESPMOD functionality\n");
  if(init_bassdrum_respmod()){
        ec_delete(ec);
        repnet_destroy(global_repnet);
        stop_ntlm_handling();
        sfilter_destroy();
        Free(auth_token_hmac_key);
        return -1;
  }

  if(regcommands(commands)){
    stop_bassdrum_respmod();
    ec_delete(ec);
    repnet_destroy(global_repnet);
    stop_ntlm_handling();
    sfilter_destroy();
    Free(auth_token_hmac_key);
    return -1;
  }

  pthread_mutex_lock(&handlerlock);
  handler_initialized = 1;
  pthread_mutex_unlock(&handlerlock);

  return 0;
}

int rep_destroy(void) {
	int wants_shutdown = 0,ret = 0;

	pthread_mutex_lock(&handlerlock);
	if(handler_initialized && !handler_closing){
		wants_shutdown = handler_closing = 1;
	}
	pthread_mutex_unlock(&handlerlock);
	if(!wants_shutdown){
		return 0;
	}
	nag("Disabling configuration changes\n");
	delcommands(commands);
	ret |= stop_bassdrum_respmod();
	nag("Destroying repper\n");
	repnet_destroy(global_repnet);
	nag("Destroying ec\n");
	ec_delete(ec);
	ec = NULL;
	ret |= stop_ntlm_handling();
	ret |= sfilter_destroy();
	pthread_mutex_lock(&handlerlock);
	handler_initialized = 0;
	handler_closing = 0;
	Free(auth_token_hmac_key);
	pthread_mutex_unlock(&handlerlock);
	return ret;
}

static int
printf_icap_respheader(icap_state *is,const char *fmt,...){
	ustring u = USTRING_INITIALIZER;
	va_list va;
	int ret;

	va_start(va,fmt);
	if(vprintUString(&u,fmt,va) < 0){
		ret = -1;
	}else{
		ret = add_icap_respheader(is,u.string);
	}
	va_end(va);
	reset_ustring(&u);
	return ret;
}

#define INC_STAT(stat) void inc_##stat(void){ ++bstats.stat; }
INC_STAT(maldetect);
INC_STAT(malclean);
INC_STAT(malerror);
INC_STAT(maljumbo);
INC_STAT(malbypass);
INC_STAT(malbackuptx);
#undef INC_STAT

// Check whether a test URL has been accessed and redirect to the corresponding
// web page. If redirection has taken place, VERDICT_ERROR or VERDICT_DONE will
// be returned (errors on rewrite can't be processed further). Otherwise,
// returns VERDICT_SKIP.
static verdict
check_testuri(icap_state *is, const char *requri, int (*cmpfnc)(const char*), char* (*urifnc)(void)) {
  if((*cmpfnc)(requri)){
    char *testuri;

      nag("Test URI detected\n");
      if( (testuri = (*urifnc)()) ){
        if(rewrite_icap_http_startline_flaturi(is, is->encaps.http.method, testuri, is->encaps.http.httpver) == 0) {
	  nag("Rewritten startline for test URI: [%s]\n", testuri);
	  Free(testuri);
	  return VERDICT_DONE;
        }
        Free(testuri);
      }
      return VERDICT_ERROR;
  }
  return VERDICT_SKIP;
}

// Extract WSD cookie data from the cookie header and remove it before sending it
// to the browser. Returns 1 if the cookie was modified, -1 on error.
static int
parse_and_purge_auth_cookie(icap_state *is, char **auth, char **user) {
  int ret = 0;

  if(is->encaps.http.cookie){
    CookieNodeType *cookie_list;
    ustring cookie_mod = USTRING_INITIALIZER;

    //nag("cookie: %s\n", is->encaps.http.cookie);
    cookie_list = parse_cookies(is->encaps.http.cookie);
    if((ret = filter_swps_cookies(&cookie_list, auth, user))) {
      if(rebuild_cookie(cookie_list, &cookie_mod)) {
	bitch("Couldn't rebuild cookie\n");
	ret = -1;
      }else{
        if(rewrite_icap_http_header(is, "Cookie:", cookie_mod.string)){
	  ret = -1;
	}
      }
      reset_ustring(&cookie_mod);
    }
    //  print_cookies(cookie_list);
    delete_cookie_list(cookie_list);
  }
  return ret;
}

// Extract WSD cookie data inserted into a proprietary HTTP header by the WFA
static void
parse_sweb_auth_cookie(icap_state *is, char **auth, char **user) {
  if(is->encaps.http.x_sweb_cookie) {
    CookieNodeType *cookie_list;
    nag("X-SWEB-Cookie = [%s]\n", is->encaps.http.x_sweb_cookie);
    cookie_list = parse_cookies(is->encaps.http.x_sweb_cookie);
    (void)filter_swps_cookies(&cookie_list, auth, user);
    delete_cookie_list(cookie_list);
  }
}

// Send a lookup using librep, returns -1 on error.
static int
do_repper_query(icap_state *is, unsigned int eid, unsigned int pid, unsigned int uid,
		unsigned int gid, uint32_t nip, const char *requri, int is_blacklisted) {
  struct rep_data *rd;
  rep_query *rq;

  rq = repquery_init(global_repnet);
  if(!rq) {
    bitch("Error on repquery_init\n");
    return -1;
  }

  if((rd = Malloc("repdata",sizeof(struct rep_data))) == NULL){
    repquery_destroy(rq);
    return -1;
  }
  rd->rq = rq;
  rd->eid = eid;
  rd->pid = pid;
  rd->uid = uid;
  rd->gid = gid;
  rd->client_ip = nip;
  rd->okey = is->encaps.hdrs;
  rd->method = Strdup(is->encaps.http.method);
  rd->httpver = Strdup(is->encaps.http.httpver);
  // FIXME use smartfilter preparation here, as well...but perhaps with a
  // distinct variable? hrmmm.
  rd->url = Strdup(requri);
  if(!rd->url || !rd->method || !rd->httpver){
    free_repdata(rd);
    return -1;
  }
  rd->is_blacklisted = is_blacklisted;

  repquery_newquery(rq);
  repquery_newchunk(rq, C_IM);
  repquery_addflags(rq, Q_FLAG_URLCATREQ);
  repquery_beginurl(rq);
  repquery_addurl(rq, requri);
  repquery_endurl(rq);
  repquery_closequery(rq);

  Gettimeofday(&rd->dispatch_time,NULL);
  if(repnet_send(global_repnet, rq, rd) != eLR_OK) {
    free_repdata(rd);
    bitch("Error on repnet_send\n");
    return -1;
  }
  return 0;
}

static int
use_ntlm_browser_workaround(const icap_state *is) {
  if(!is->encaps.http.user_agent) {
    return 0;
  }
  return !!strstr(is->encaps.http.user_agent, "MSIE 6.0");
}

// user identification using ntlm; returns -1 on error, 0 on success
static int
ntlm_user_identification(icap_state *is, char *c_user, char *c_auth, uint32_t nip,
			 unsigned int eid, unsigned int *newuid, int *redir_immediately,
			 int check_password) {
  int ret = -1;
  char *ep;
  char *proxyauth = NULL;
  char *scheme, *authdata;
  char *enccook = NULL;
  unsigned char *dec = NULL;
  size_t len;
  ntlm_type3_data t3data;
  ustring us = USTRING_INITIALIZER;

  reset_type3_data(&t3data);
  *redir_immediately = 0;
  *newuid = 0;

  nag("Password check flag is %d\n", check_password);

  // Do we already have a valid cookie with data for NTLM?
  nag("Check cookie\n");
  if(c_auth && c_user && c_user[0] == 'n' && check_auth_cookie(c_auth, c_user, nip, time(0), NTLM_AUTH_TIME_WINDOW)) {
    c_user++; // skip the 'n';
    *newuid = strtoul(c_user, &ep, 10); // skip the 'c' in the user string
    if(ep[0]) {
      bitch("Invalid user information in cookie\n");
    } else {
      // Success! We retrieved the data from an NTLM-triggered cookie.
      ret = 0;
      goto cleanup;
    }
  }

  // Check if we have a proxy authorization header
  nag("Check auth hdr\n");
  if(!is->encaps.http.proxyauth) {
    *redir_immediately = 1;
    ret = reqresp_ntlm_challenge(is);
    goto cleanup;
  }

  // Check if we have an NTLM auth header
  nag("Check ntlm auth hdr\n");
  proxyauth = Strdup(is->encaps.http.proxyauth);
  if(!proxyauth) {
    goto cleanup;
  }
  authdata = proxyauth;
  scheme = strsep(&authdata, " ");
  if(!scheme || !authdata || strcmp(scheme, "NTLM")) {
    *redir_immediately = 1;
    ret = reqresp_ntlm_challenge(is);
    goto cleanup;
  }

  // Alright, so we should have NTLM auth data from the client now. Let's see
  // what it is...
  nag("Decode\n");
  dec = base64_bin_decode(authdata, &len);
  if(!dec) {
    goto cleanup;
  }
 
  // A type 1 maybe?
  nag("Check for type 1\n");
  if(ntlm_check_if_type1(dec, len)) {
    // We got a type 1 message here
    *redir_immediately = 1;
    ret = reqresp_ntlm_type2(is, nip);
    nag("Responding with type 2\n");
    goto cleanup;
  }

  // If we're getting here, we should have gotten a type 3 message
  nag("Attempt to decode type 3\n");
  if(ntlm_decode_type3(dec, len, &t3data)) {
    nag("Error decoding type 3 message\n");
    ret = reqresp_error_msg(is, "Malformed NTLM message received from browser.");
    *redir_immediately = 1;
    goto cleanup;
  }
  nag("Successfully decoded type 3 message from user '%s' at eid %u (domain '%s', host '%s')\n",
      t3data.user, eid, t3data.domain, t3data.host);

  if(printUString(&us, "%s\\%s", t3data.domain, t3data.user) < 0) {
    goto cleanup;
  }

  nag("Looking up alias %s\n", us.string);

  *newuid = ec_get_uid_by_alias(ec, eid, us.string);
  if(!*newuid) {
    nag("User '%s' is not known for eid %u\n", t3data.user, eid);
    // fail open, set uid = 0 to set cookie so that user doesn't need to go through this again
    *newuid = 0;
  } else {
    nag("User %u identified successfully\n", *newuid);
    if(check_password) {
      const unsigned char *ntlmhash;
      nag("Checking password\n");
      ntlmhash = ec_get_pwntlmhash_by_uid(ec, *newuid);
      if(!ntlmhash) {
	nag("User has no NTLM password set\n");
	*newuid = 0;
      } else {
	int ntlmres;
	ntlmres = ntlm_verify_password(dec, len, ntlmhash, nip);
	if(ntlmres == 0) {
	  nag("Password ok\n");
	} else if(ntlmres == -1) {
	  nag("Error during password verification\n");
	  *newuid = 0;
	} else if(ntlmres == 1) {
	  char *failuri;
	  nag("Invalid password\n");
	  *newuid = 0;
	  if((failuri = get_ntlm_auth_fail_uri())) {
	    // If we have a fail URI, send users there -- otherwise continue
	    nag("Redirecting to %s\n", failuri);
	    ret = reqresp_redirect(is, failuri);
	    Free(failuri);
	    *redir_immediately = 1;
	    goto cleanup;
	  }
	}
      }
    }
  }

  // Encrypt data and put it into header to be picked up in RESPMOD
  enccook = gen_ntlm_cookie_data(nip, *newuid, time(0));
  if(!enccook) {
    nag("Generating cookie data failed\n");
    goto cleanup;
  }
  
  if(rewrite_icap_http_header(is, HDR_NTLM_STATE, enccook)) {
    nag("Rewriting header failed\n");
    goto cleanup;
  }

  ret = 0;
 cleanup:
  Free(proxyauth);
  Free(dec);
  Free(enccook);
  free_type3_data(&t3data);
  reset_ustring(&us);
  return ret;
}

// user auth over cookies; returns -1 on error, 0 on success
static int
user_authentication(icap_state *is, const char *requri, uint32_t nip, char *c_auth, char *c_user,
		    int use_ntlm, unsigned int saml_eid, unsigned int *uid, int *redirect_immediately) {
  char *returl = NULL, *ep, *pos;
  unsigned int auid;
  long ts;
  int have_auth = c_auth && c_user;
  const char *redirurl;
  int ret;

  *uid = 0;

  if(is_https(is)) {
    *redirect_immediately = 0;
    nag("Skipping cookie-based authentication for https\n");
    return 0;
  }

  if(!have_auth) {
    if(add_icap_respheader(is, "X-ICAP-RESPMOD-Profile: NoRESPMOD")){
      return -1;
    }
  }
  
  *redirect_immediately = 1;

  if((pos = strstr(requri, AUTH_DOM_COOKIE_CHECK_SUFFIX))) {
    // When the check suffix is detected, a cookie should be present. Otherwise,
    // alert the user to the fact that a cookie is missing.
    if(have_auth) {
      // Cookie is there, we're all good. Remove the suffix and proceed
      returl = Strdup(requri);
      if(!returl) {
	// No memory, just leave the suffix in the URL and move on
	*redirect_immediately = 0;
	return 0;
      }
      returl[pos - requri] = '\0';
      ret = reqresp_redirect(is, returl);
      Free(returl);
      return ret;
    } else {
      // No cookie even though there should be one... Alert the user
      char *cookies_disabled_uri;
      if((cookies_disabled_uri = get_cookies_disabled_uri())) {
	ret = reqresp_redirect(is, cookies_disabled_uri);
	Free(cookies_disabled_uri);
	return ret;
      } else {
	// No cookie disabled URI, return with an error to avoid a
	// redirection loop
	bitch("No cookies_disabled_uri\n");
	return -1;
      }
    }
  }
  
  // Were we redirected to this location by the auth server?
  if(check_auth_token(requri, &returl, nip, &auid, &ts, time(0))) {
    nag("valid auth token\n");
    ret = reqresp_redirect_auth_token_to_cookie(is, returl, nip, auid, ts);
    Free(returl);
    return ret;
  }

  // Check if we have a valid cookie
  if(have_auth && check_auth_cookie(c_auth, c_user, nip, time(0), auth_time_window) && c_user && c_user[0] == 'c') {
    Free(returl);
    nag("valid auth cookie\n");
    *redirect_immediately = 0;
    *uid = strtoul(c_user + 1, &ep, 10); // skip the 'c' in the user string
    if(ep[0]) {
      bitch("Invalid user information in cookie\n");
      // same action as for invalid cookie below, need to pull this into one statement
      if(add_icap_respheader(is,"X-Attribute: action: auth_redir") < 0) {
	return -1;
      }
      return reqresp_redirect_for_auth(is, requri, nip, use_ntlm, saml_eid);
    }
    return 0;
  }

  // Check if we have an invalid cookie
  if(have_auth) {
    Free(returl);
    bitch("auth cookie present but invalid\n");
    nag("Sending user to auth page (1)\n");
    if(add_icap_respheader(is,"X-Attribute: action: auth_redir") < 0) {
      return -1;
    }
    return reqresp_redirect_for_auth(is, requri, nip, use_ntlm, saml_eid);
  }

  // No cookie, not coming from auth server ==> not authorized
  nag("No auth cookie found\n");

  // Is user trying to access auth page objects?
  if(cmpn_login_uri_prefix(requri) || cmpn_ntlm_workaround_uri_prefix(requri)) {
    // Let user access the auth page
    Free(returl);
    nag("Allowing auth page access\n");
    if(add_icap_respheader(is,"X-Attribute: action: auth_page") < 0) {
      return -1;
    }
    return 0;
  }
  
  // If there was an invalid auth token, then remove it for the redirect
  if(returl) {
    redirurl = returl;
  } else {
    redirurl = requri;
  }
  nag("Sending user to auth page (2)\n");
  if(add_icap_respheader(is,"X-Attribute: action: auth_redir") < 0) {
    Free(returl);
    return -1;
  }
  ret = reqresp_redirect_for_auth(is, redirurl, nip, use_ntlm, saml_eid);
  Free(returl);
  return ret;
}

// Authentication via Proxy-Authorization header. Returns true if valid data
// was submitted and false otherwise.
static int
proxy_authentication(icap_state *is, uint32_t nip, unsigned int *uid, unsigned int *pid,
		     unsigned int *eid, unsigned int *gid, unsigned int *vid, int *stale) {
  int ret = 0;

  *stale = 0;
  *vid = 0;

  if(!is->encaps.http.proxyauth) {
    // No Proxy-Authorization header
    goto cleanup;
  }
  nag("proxyauth is [%s]\n", is->encaps.http.proxyauth);
  
  ret = check_authorization_header(is->encaps.http.proxyauth,
				   is->encaps.http.method, nip,
				   internal_hmac_key, uid, vid, stale);

  if(ret) {
    nag("Retrieving policy data for uid %u\n", *uid);
    ec_get_pol_data_for_uid(ec, *uid, pid, eid, gid);
  } else {
    nag("Authorization header was invalid\n");
  }

  bstats.vid_size = get_current_vid_size();

 cleanup:
  return ret;
}

// Attempt to authenticate using headers provided by mobile client tool.
static int
mobile_client_authentication(icap_state *is, const char *requri,
			     unsigned int *uid, unsigned int *pid,
			     unsigned int *eid, unsigned int *gid) {
  const char *timestamp = is->encaps.http.x_scurweb_authts;
  int64_t ts;
  long delta;

  if(!(is->encaps.http.x_scurweb_authversion
       && is->encaps.http.x_scurweb_authuser
       && is->encaps.http.x_scurweb_authts
       && is->encaps.http.x_scurweb_authtoken
       && is->encaps.http.x_scurweb_authcompanyid)) {
    return 0;
  }  
  
  if(lex_s64(&timestamp, &ts)) {
    nag("Lexing timestamp failed\n");
    return 0;
  }

  delta = (long)time(0) - (long)ts;
  if(labs(delta) > auth_time_window) {
    nag("Auth data expired\n");
    return 0;
  }

  return mobclt_auth(ec,
		     is->encaps.http.x_scurweb_authcompanyid,
		     requri,
		     is->encaps.http.x_scurweb_authversion,
		     is->encaps.http.x_scurweb_authuser,
		     is->encaps.http.x_scurweb_authts,
		     is->encaps.http.x_scurweb_authtoken,
		     uid, pid, eid, gid);
}

static int
remove_scurweb_headers(icap_state *is) {
  if(is->encaps.http.x_scurweb_authversion) {
    if(rewrite_icap_http_header(is, "X-SWEB-AuthVersion:", NULL)) {
	    return -1;
    }
  }
  if(is->encaps.http.x_scurweb_authuser) {
    if(rewrite_icap_http_header(is, "X-SWEB-AuthUser:", NULL)) {
	    return -1;
    }
  }
  if(is->encaps.http.x_scurweb_authts) {
    if(rewrite_icap_http_header(is, "X-SWEB-AuthTS:", NULL)) {
	    return -1;
    }
  }
  if(is->encaps.http.x_scurweb_authtoken) {
    if(rewrite_icap_http_header(is, "X-SWEB-AuthToken:", NULL)) {
	    return -1;
    }
  }
  if(is->encaps.http.x_scurweb_authcompanyid) {
    if(rewrite_icap_http_header(is, "X-SWEB-AuthCustID:", NULL)) {
	    return -1;
    }
  }
  if(is->encaps.http.x_sweb_cookie) {
    if(rewrite_icap_http_header(is, "X-SWEB-Cookie:", NULL)) {
	    return -1;
    }
  }
#define SWEB_CLIENT_REMOVE(vname, hname) \
  if(is->encaps.http.x_sweb_client ## vname) { \
    if(rewrite_icap_http_header(is, "X-SWEB-Client" #hname ":", NULL)) { \
	    return -1; \
    } \
  }
  SWEB_CLIENT_REMOVE(vendor, Vendor)
  SWEB_CLIENT_REMOVE(serial, Serial)
  SWEB_CLIENT_REMOVE(mac, MAC)
  SWEB_CLIENT_REMOVE(ip, IP)
  SWEB_CLIENT_REMOVE(model, Model)
  SWEB_CLIENT_REMOVE(version, Version)
#undef SWEB_CLIENT_REMOVE
  return 0;
}

// Called from handler for CONNECT requests, returns true if handler should return
static int
enforce_connect_ports(icap_state *is, const char *requri) {
  size_t s;
  uint16_t port;

  for(s = strlen(requri); s; s--) {
    if(requri[s] == ':') {
      break;
    }
  }
  if(s) {
    requri += s + 1;
    if(lex_u16(&requri, &port)) {
      reqresp_error(is);
      return -1;
    }
    if(is_allowed_port(port)) {
      return 0;
    } else {
      // Need something more fancy here
      reqresp_error_msg(is, "A connection to an illegal port was attempted.");
      return -1;
    }
  }
  reqresp_error(is);
  return -1;
}

// FIXME break up this function. It's impossible to follow.
static verdict
policy_handler(icap_state *is, const char *requri)
{
  ActionType action;
  uint32_t nip;
  unsigned int eid = 0, pid = 0, gid = 0;	// entity id, policy id, group id
  char *c_auth = NULL, *c_user = NULL;
  char *xc_auth = NULL, *xc_user = NULL;
  unsigned int uid = 0;	// user id (for users and netblocks)
  const char *host;
  int is_blacklisted = 0;
  size_t pos;
  int redirect_immediately, stale;
  int cookie_auth_profile = 0;	// the proxy requested to use cookie auth instead of proxy auth if all other methods fail
  int use_cookie_ntlm_auth = 0;	// use the cookie auth page to retrieve ntlm data (for IE6 workaround)
  int use_ntlm = 0;		// use NTLM on IP range
  int use_ip_cookieauth = 0;	// use cookie auth on IP range (different from fallback cookie auth)
  int saml_eid = 0;		// eid for cookie auth triggered by mobile client (used for SAML), otherwise 0
  int using_ip_auth = 0;
  int ppac;			// result of parse_and_purge_auth_cookie
  int is_pac;			// URL is for PAC file
  verdict v;
  const char *testuri;
  int authtype = AUTH_NONE;
  unsigned long port_eid = 0;	// For CCE hack
  int port_auth = 0;

  if(is_https(is)) {
    if(enforce_connect_ports(is, requri)) {
      // xxx fixme: because we don't send an error back in the function above,
      // an error just results in returning here, which is not desired
      // ... even if a port is blocked, we end up sending a verdict_done here,
      // this is quite broken now :(
      return VERDICT_DONE;
    }
  }

  if((v = check_testuri(is, requri, &cmp_localtesturi, &get_testuri)) != VERDICT_SKIP){
    return v;
  }
  if((v = check_testuri(is, requri, &cmp_localtest2uri, &get_test2uri)) != VERDICT_SKIP){
    return v;
  }

  if((testuri = testuri_lookup(requri))) {
    if(rewrite_icap_http_startline_flaturi(is, is->encaps.http.method, testuri, is->encaps.http.httpver) == 0) {
      nag("Rewritten startline for test URI map: [%s] -> [%s]\n", requri, testuri);
      return VERDICT_DONE;
    }
    ++bstats.uri_error;
    return VERDICT_ERROR;
  }

  host = is->headers.host;
  if(is->headers.client_ipstr == NULL) {
    bitch("No client IP found\n");
    if(reqresp_error(is)) {
      ++bstats.header_error;
      return VERDICT_ERROR;
    } else {
      return VERDICT_DONE;
    }
  }
  if(parse_ipv4address(is->headers.client_ipstr, &nip) <= 0) {
    if(reqresp_error(is)) {
      ++bstats.uri_error;
      return VERDICT_ERROR;
    } else {
      return VERDICT_DONE;
    }
  }
  nip = ntohl(nip);

  nag("Client IP is %s", is->headers.client_ipstr);

  if(is->encaps.http.user_agent) {
    nag("User agent is [%s]\n", is->encaps.http.user_agent);
  }

  if((ppac = parse_and_purge_auth_cookie(is, &c_auth, &c_user)) > 0) {
    nag("Cookie was modified\n");
  }else if(ppac < 0){
    Free(c_auth);
    Free(c_user);
    if(reqresp_error(is)) {
      ++bstats.cookie_error;
      return VERDICT_ERROR;
    } else {
      return VERDICT_DONE;
    }
  }

  if(is->icapuri && is->icapuri->query) {
    if(strcmp(is->icapuri->query, COOKIE_AUTH_PROFILE_STRING) == 0) {
      nag("Using cookie auth\n");
      cookie_auth_profile = -1;
      ++bstats.cookie_profile;
    } else if(strncmp(is->icapuri->query, PORT_EID_PROFILE_STRING, strlen(PORT_EID_PROFILE_STRING)) == 0) {
      const char *peid = is->icapuri->query + strlen(PORT_EID_PROFILE_STRING);
      char *ep;
      if(peid[0] == 'A') {
	nag("Auth option for port_eid enabled\n");
	port_auth = -1;
	peid++;
      }
      ++bstats.port_profile;
      port_eid = strtoul(peid, &ep, 10); // skip the 'c' in the user string
      if(ep[0]) {
	bitch("Error in port_eid string\n");
	Free(c_auth);
	Free(c_user);
	return VERDICT_ERROR;
      }
      nag("Using port_eid %lu\n", port_eid);
    } else {
      bitch("Unknown ICAP query string [%s]\n", is->icapuri->query);
      Free(c_auth);
      Free(c_user);
      c_auth = c_user = NULL;
      // This is a WW config issue, error out
      return VERDICT_ERROR;
    }
  } else {
    ++bstats.no_profile;
  }

  // Always allow access to swps pages (external objects for other pages are hosted here)
  if(cmpn_swpsuri(requri)) {
    nag("SWPS page -- allow\n");
    // xxx eid is still 0 here
    if(printf_icap_respheader(is,"X-Attribute: eid: %u; action: allow; detail: swps_page", eid) < 0) {
      Free(c_auth);
      Free(c_user);
      if(reqresp_error(is)) {
        ++bstats.header_error;
        return VERDICT_ERROR;
      } else {
        return VERDICT_DONE;
      }
    }
    Free(c_auth);
    Free(c_user);
    return VERDICT_DONE;
  }

  is_pac = cmp_pacuri(requri) || cmp_pacuri2(requri);

  // WFA cached auth cookie
  nag("Next auth scheme: WFA/SWEB-Cookie\n");
  parse_sweb_auth_cookie(is, &xc_auth, &xc_user);
  if(xc_auth && xc_user) {
    nag("xc_auth = [%s], xc_user = [%s]\n", xc_auth, xc_user);
    if(check_auth_cookie(xc_auth, xc_user, nip, time(0), auth_time_window)) {
      char *ep;
      nag("Valid cached credentials in WFA header\n");
      uid = strtoul(xc_user + 1, &ep, 10); // skip the 'c' in the user string
      if(ep[0]) {
	bitch("Invalid user information in cookie\n");
        ++bstats.cookie_error;
      } else {
	ec_get_pol_data_for_uid(ec, uid, &pid, &eid, &gid);
	if(eid) {
	  nag("Uid %u in WFA cookie header known, using pid %u, eid %u, gid %u\n", uid, pid, eid, gid);
	  Free(xc_auth);
	  Free(xc_user);
	  ++bstats.auth_wfa_cookie;
          authtype = AUTH_WFA_SWEB_COOKIE;
	  goto have_eid;
	}
      }
    }
  }
  Free(xc_auth);
  Free(xc_user);

  // See if the company id from the WFA has SAML activated
  // xxx We do not verify the entity password here -- Do we need to?
  nag("Next auth scheme: WFA/SAML\n");
  if(is->encaps.http.x_scurweb_authcompanyid) {
    const char *company_id = is->encaps.http.x_scurweb_authcompanyid;
    uint32_t wfa_eid;
    if(lex_u32(&company_id, &wfa_eid)) {
      nag("Lexing company_id failed\n");
    } else {
      if(ec_get_wfa_saml_flag(ec, wfa_eid)) {
	nag("WFA SAML flag for eid %u is set\n", wfa_eid);
	if(ec_is_auth_page(ec, wfa_eid, requri)) {
	  nag("Auth page for customer %u -- allow", wfa_eid);
	  Free(c_auth);
	  Free(c_user);
	  return VERDICT_DONE;
	}
	if(is_https(is)) {
	  nag("Skipping SAML for HTTPS\n");
	} else {
	  nag("Continuing with cookie auth for SAML\n");
	  saml_eid = wfa_eid;
	  ++bstats.auth_wfa_saml;
	  goto cookieauth;
	}
      }
    }
  }

  // WFA user authentication
  nag("Next auth scheme: WFA/native\n");
  (void)mobile_client_authentication(is, requri, &uid, &pid, &eid, &gid);
  if(eid) {
    nag("Mobile client data valid, using uid %u, pid %u, eid %u, gid %u\n", uid, pid, eid, gid);
    ++bstats.auth_wfa_native;
    authtype = AUTH_WFA_NATIVE;
    goto have_eid;
  }

  if(is->encaps.http.x_scurweb_authagentonly && strcasecmp(is->encaps.http.x_scurweb_authagentonly, "true") == 0) {
    nag("Client requested WFA authentication only, giving up\n");
    Free(c_auth);
    Free(c_user);
    c_auth = c_user = NULL;
    ++bstats.auth_none;
    return reqresp_noauth_403(is) ? VERDICT_ERROR : VERDICT_DONE;
  }

  // IP auth
  nag("Next auth scheme: IP\n");
  ec_get_pol_data_for_ip(ec, nip, &uid, &pid, &eid, &gid, &use_ntlm, &use_ip_cookieauth);
  if(eid) {
    ++bstats.auth_ip;
    using_ip_auth=1;
    nag("Client IP known, using uid %u, pid %u, eid %u, gid %u\n", uid, pid, eid, gid);
    nag("NTLM flag for IP is %d, cookie/IP auth flag is %d\n", use_ntlm, use_ip_cookieauth);

    if(!is_https(is) && use_ntlm_browser_workaround(is) && use_ntlm && !is_pac && !is_ntlm_excl_ua(is->encaps.http.user_agent) && !cookie_auth_profile) {
      // NTLM for IE6 -- use ulogin to get credentials
      nag("Using NTLM workaround\n");
      use_cookie_ntlm_auth = -1;
      ++bstats.auth_ip_ntlm_workaround;
      authtype = AUTH_NTLM_IE6;
      saml_eid = eid; // xxx not SAML, need to rename var
      goto cookieauth; // xxx This is just terrible :( http://xkcd.com/292/
    } 
    if(use_ntlm && !is_pac && !is_ntlm_excl_ua(is->encaps.http.user_agent) && !cookie_auth_profile) {
      // Only do NTLM if...
      // * it is configured for this IP range
      // * the user agent is not on the exclusion list
      // * the proxy did not request cookie auth (implies explicit proxy configuration, which is needed for the 407)
      unsigned int ntlm_uid = 0;
      
      if(ntlm_user_identification(is, c_user, c_auth, nip, eid, &ntlm_uid, &redirect_immediately, (use_ntlm == NTLM_AUTH))) {
	Free(c_auth);
	Free(c_user);
	nag("Error during NTLM user identification\n");
        ++bstats.cookie_error;
	return VERDICT_ERROR;
      }
      if(redirect_immediately) {
	Free(c_auth);
	Free(c_user);
	nag("Redirecting early for NTLM identification\n");
	return VERDICT_DONE;
      }
      if(ntlm_uid) {
	unsigned int ntlm_pid, ntlm_gid, ntlm_eid;
	ec_get_pol_data_for_uid(ec, ntlm_uid, &ntlm_pid, &ntlm_eid, &ntlm_gid);
	if(ntlm_eid) {
	  if(ntlm_eid != eid) {
	    bitch("NTLM eid is %u, but IP eid is %u. This should never occur. Ignoring NTLM data.\n", ntlm_eid, eid);
            ++bstats.ntlm_error;
	  } else {
	    pid = ntlm_pid;
	    gid = ntlm_gid;
	    uid = ntlm_uid;
	    nag("Using NTLM identification data: uid %u, pid %u, eid %u, gid %u\n", ntlm_uid, ntlm_pid, ntlm_eid, ntlm_gid);
	    using_ip_auth=0;
	    ++bstats.auth_ip_ntlm;
            authtype = AUTH_IP_NTLM;
	  }
	} else {
	  bitch("No user data found for uid %u retrieved during NTLM identification, using IP data.\n", ntlm_uid);
          ++bstats.ntlm_error;
	}
      } else {
	nag("No user data for NTLM user, using IP data.\n");
      }
    } else {
      nag("NTLM bypassed\n");
    }

    if(cookie_auth_profile && use_ip_cookieauth && using_ip_auth && ec_is_auth_page(ec, eid, requri)) {
      nag("Auth page for customer %u -- allow", eid);
      Free(c_auth);
      Free(c_user);
      return VERDICT_DONE;
    }

    if(cookie_auth_profile && use_ip_cookieauth && !is_https(is) && !is_pac && !is_cookie_excl_ua(is->encaps.http.user_agent) && using_ip_auth) {
      // Attempt cookie auth on this IP range if configured and if we have no NTLM-based uid
      nag("Using cookie/IP auth\n");
      saml_eid = eid;
      using_ip_auth = 0;
      ++bstats.auth_ip_cookie;
      authtype = AUTH_IP_COOKIE;
      goto cookieauth;
    } else {
      nag("Cookie/IP auth bypassed\n");
    }

    authtype = AUTH_IP;
    goto have_eid;
  }

  // Port EID/NTLM auth
  if(port_eid) {
    nag("Next auth scheme: Port EID for NTLM\n");
    if(!is_https(is) && use_ntlm_browser_workaround(is) && !is_pac && !is_ntlm_excl_ua(is->encaps.http.user_agent)) {
      nag("Using NTLM workaround\n");
      use_cookie_ntlm_auth = -1;
      ++bstats.auth_port_ntlm_ie6;
      authtype = AUTH_NTLM_IE6;
      saml_eid = port_eid; // xxx not SAML, need to rename var
      goto cookieauth; // xxx This is just terrible :(
    }
    if(!is_pac && !is_ntlm_excl_ua(is->encaps.http.user_agent)) {
      if(ntlm_user_identification(is, c_user, c_auth, nip, port_eid, &uid, &redirect_immediately, port_auth)) {
	Free(c_auth);
	Free(c_user);
	nag("Error during NTLM user identification\n");
	return VERDICT_ERROR;
      }
      if(redirect_immediately) {
	Free(c_auth);
	Free(c_user);
	nag("Redirecting early for NTLM identification\n");
	return VERDICT_DONE;
      }
      if(uid) {
	ec_get_pol_data_for_uid(ec, uid, &pid, &eid, &gid);
	if(eid) {
	  if(port_eid != eid) {
	    bitch("Eid mismatch\n");
	  } else {
	    authtype = AUTH_PORT_NTLM;
	    ++ bstats.auth_port_ntlm;
	    goto have_eid;
	  }
	} else {
	  bitch("No user data found for uid %u retrieved during NTLM identification\n", uid);
	}
      } else {
	nag("No user data for NTLM user\n");
      }
    }
  }

  if(check_for_generic_pac(is, requri, &v)) {
    Free(c_auth);
    Free(c_user);
    // If the request was for the pac file, then send the generic one
    return v;
  }

  if(cookie_auth_profile) {
    // User/login page auth
    ++bstats.auth_cookie;
  cookieauth:
    nag("Next auth scheme: Cookie\n");
    // Saml_eid is non-zero if we came here via the WFA/SAML auth scheme or via the IP/Cookie auth scheme.
    // It is used by ulogin.php to determine whether SAML is activated for this request (this customer).
    //
    // xxx Saml_eid is now also used by the IE6 NTLM workaround and has nothing to do with SAML in that
    // case. Need to rename it.
    if(user_authentication(is, requri, nip, c_auth, c_user, use_cookie_ntlm_auth, saml_eid, &uid, &redirect_immediately)) {
      Free(c_auth);
      Free(c_user);
      nag("Error in user_authentication()\n");
      ++bstats.auth_error;
      return VERDICT_ERROR;
    }
    Free(c_auth);
    Free(c_user);
    c_user = c_auth = NULL;
    
    if(redirect_immediately) {
      return VERDICT_DONE;
    }
    ec_get_pol_data_for_uid(ec, uid, &pid, &eid, &gid);
    if(eid) {
      nag("Uid %u in cookie known, using pid %u, eid %u, gid %u\n", uid, pid, eid, gid);
      if(saml_eid && authtype != AUTH_IP_COOKIE && authtype != AUTH_NTLM_IE6) {
        authtype = AUTH_WFA_SAML;
      } else {
        if(authtype == AUTH_NONE) {
          authtype = AUTH_COOKIE;
        }
      }
      goto have_eid;
    }

    // If we got here due to the IE6 NTLM workaround and the alias was not found by ulogin.php, then
    // use IP data instead.
    if(use_ntlm) {
      nag("Redoing IP auth for unknown user for NTLM IE6 workaround\n");
      ec_get_pol_data_for_ip(ec, nip, &uid, &pid, &eid, &gid, &use_ntlm, &use_ip_cookieauth);
      if(eid) {
        authtype = AUTH_IP;
	goto have_eid;
      }
    }

  } else {
    // Proxy auth
    unsigned int vid;

    Free(c_auth);
    Free(c_user);
    c_user = c_auth = NULL;

    nag("Next auth scheme: Proxy\n");
    if(!proxy_authentication(is, nip, &uid, &pid, &eid, &gid, &vid, &stale)) {
      ++bstats.auth_proxy;
      if(vid) {
	nag("Client provided verified vid %u\n", vid);
      } else {
	vid = (unsigned int)(labs(random()) & 0xffffffff);
	nag("Generating new vid for client: %u\n", vid);
      }
      if(reqresp_redirect_for_proxy_auth(is, nip, internal_hmac_key, vid, stale)) {
        ++bstats.auth_error;
        return VERDICT_ERROR;
      } else {
        return VERDICT_DONE;
      }
    }
    if(eid) {
      ++bstats.auth_proxy;
      nag("Uid %u retrieved from proxy auth, using pid %u, eid %u, gid %u\n", uid, pid, eid, gid);
      authtype = AUTH_PROXY;
      goto have_eid;
    }
  }

  // All auth methods failed
  ++bstats.auth_none;
  nag("Uid %u unknown, denying service\n", uid);
  if(printf_icap_respheader(is,"X-Attribute: eid: %u; action: error; detail: noauth_user", eid) < 0) {
    ++bstats.header_error;
    return VERDICT_ERROR;
  }
  if(reqresp_noauth(is, nip)) {
    ++bstats.auth_error;
    return VERDICT_ERROR;
  } else {
    return VERDICT_DONE;
  }

 have_eid:
  // Auth succeeded

  // nag("Policy URL list check\n");
  Free(c_auth);
  Free(c_user);
  c_auth = c_user = NULL;

  if(remove_scurweb_headers(is)){
    if(reqresp_error(is)) {
      ++bstats.header_error;
      return VERDICT_ERROR;
    } else {
      return VERDICT_DONE;
    }
  }

  // Remove proxy auth header (but not on URIs below the whomai page)
  if(!(pos = cmpn_whoami_uri(requri))){
    if(rewrite_icap_http_header(is, "Proxy-Authorization:", NULL)) {
      if(reqresp_error(is)) {
        ++bstats.header_error;
        return VERDICT_ERROR;
      } else {
        return VERDICT_DONE;
      }
    }
  }

  action = ec_apply_policy_url_lists(ec, pid, requri);

  // Is this URL the block/noauth URL specified in the config? We need this as
  // redirection target for HTTPS block/noauth pages (Bug 311/Bug 348).
  // xxx need to encode rule name here as well
  if((pos = cmpn_blockuri(requri))){
    char *url;
    SiteInfoType blsi = SITEINFOTYPE_INITIALIZER;

    nag("Sending block page\n");
    nag("Decoding addtional data: [%s]\n", requri + pos);
    if(!decode_block_page_data(requri + pos, &url, &blsi, -1)) {
      bitch("Error decoding data\n");
      reqresp_error_msg(is, "Invalid data in block page URL");
      ++bstats.uri_error;
    } else {
      // There is a chance that the rule_id we decoded into blsi is not present
      // anymore (race condition if the admin deleted the rule and the policy
      // was reloaded while the user was redirected to the block page). In that
      // case the reqresp_blocked code will use "--" as the rule name. This
      // should happen very rarely (only HTTPS, only when rule that hit got
      // deleted during redirection time window).
      reqresp_blocked_by_rule(is, ec_get_block_page(ec, pid), url, &blsi);
      Free(url);
      reset_siteinfotype(&blsi);
    }
    return VERDICT_DONE;
  }
  if(cmp_noauthuri(requri)){
      nag("Sending noauth page\n");
      // xxx if you navigate to the noauth page directly, it'll say your IP
      //     is not authorized even though it may be...
      reqresp_noauth(is, nip);
      return VERDICT_DONE;
  }

  if(action == ACT_BLOCK) {
    nag("Block -- blacklisted, fetching category information\n");
    is_blacklisted = 1;
    // We can't return a block page yet because we need to fetch category data over librep first
  } else if(action == ACT_ALLOW) {
    nag("Allow -- whitelisted\n");
    if(printf_icap_respheader(is,"X-Attribute: eid: %u; uid: %u; gid: %u; action: allow; detail: whitelisted", eid, uid, gid) < 0) {
      reqresp_error(is);
      return VERDICT_DONE;
    }
    if(add_icap_respheader(is, "X-SSL-Request: Tunnel")){
      ++bstats.header_error;
      return VERDICT_ERROR;
    }
    if(rewrite_icap_http_header(is, "X-SWEB-Flags:", "1")) {
      nag("Adding header failed\n");
      ++bstats.header_error;
      return VERDICT_ERROR;
    }
    return VERDICT_DONE;
  } else if(action == ACT_ERROR) {
    nag("An error occured\n");
    printf_icap_respheader(is,"X-Attribute: eid: %u; uid: %u; gid: %u; action: error", eid, uid, gid);
    reqresp_error_msg(is, "Missing or invalid policy data.");
    return VERDICT_DONE;
  } else if(action == ACT_ERROR_NOAUTH) {
    nag("No authentication\n");
    if(printf_icap_respheader(is,"X-Attribute: eid: %u; uid: %u; gid: %u; action: error; detail: noauth", eid, uid, gid) < 0) {
      reqresp_error(is);
      return VERDICT_DONE;
    }
    reqresp_noauth(is, nip);
    return VERDICT_DONE;
  }

  if(is_pac){
      nag("Sending PAC\n");
      if(reqresp_pacfile(is, ec_get_pac_file(ec, eid))) {
        ++bstats.pac_error;
        return VERDICT_ERROR;
      } else { 
	return VERDICT_DONE;
      }
  }

  if(cmp_whoami_uri(requri)){
      nag("Sending whoami page\n");
      return reqresp_whoami(is, eid, gid, uid, pid, nip, using_ip_auth, authtype) ? VERDICT_ERROR : VERDICT_DONE;
  }

  /* Continue with librep query */
  if(do_repper_query(is, eid, pid, uid, gid, nip, requri, is_blacklisted)) {
    reqresp_error(is);
    return VERDICT_DONE;
  }

  nag("Sent repquery, waiting for callback\n");
  // Don't perform any verdict right now -- the handler will, instead.
  return VERDICT_COUNT;
}

static verdict
reqmod_handler(struct oqueue_key *oqk,icap_state *is,icap_callback_e status){
	verdict v = VERDICT_ERROR;
	char *requri = NULL;
	struct timeval reqmod_start_time;
	
	if(status != ICAP_CALLBACK_HEADERS){
		// We don't want to examine bodies. If we return a verdict,
		// we'll not be passed the body, never reaching this block. So,
		// we must still be waiting on a verdict. Keep waiting...
		nag("Skipping REQMOD body on %d\n",oqk->cbarg->pfd.fd);
		return VERDICT_SKIP;
	}
	if(!(is->encaps.http.rawuri && is->encaps.http.method && is->encaps.http.httpver)){
		bitch("Missing startline components\n");
		goto done;
	}
	if((requri = sfilter_uri_generate(is)) == NULL){
		goto done;
	}
	Gettimeofday(&reqmod_start_time, NULL);
	if((v = policy_handler(is,requri)) == VERDICT_COUNT){
		update_avgmax(&bstats.handler_auth_time, &reqmod_start_time);
		if(add_timeout_to_pollqueue(snarepoller,TIMEOUT_SEC * 1000,
				oqk->cbarg->pfd.fd,timeout_reprx)){
			v = VERDICT_ERROR;
			// FIXME memory leak? what happens to *rd now?
		}
	} else {
	  update_avgmax(&bstats.handler_auth_time, &reqmod_start_time);
	}
	
done:
	Free(requri);
	if(v == VERDICT_ERROR){
		if(reqresp_error(is) == 0){
			v = VERDICT_DONE;
		}
	}
	return v;
}

verdict r_handler(struct oqueue_key *oqk,icap_state *is,icap_callback_e status){
	verdict v;

	switch(is->method){
		case ICAP_METHOD_REQMOD: v = reqmod_handler(oqk,is,status); break;
		case ICAP_METHOD_RESPMOD: {
			if((v = respmod_handler(oqk,status)) == VERDICT_COUNT){
				inc_curmax_stats(&bstats.bonblocking);
			}
		}
		break;
		case ICAP_METHOD_OPTIONS: v = VERDICT_DONE; break;
		case ICAP_METHOD_COUNT:
	       	default:
			bitch("Unknown method %d on %d\n",is->method,oqk->cbarg->pfd.fd);
			v = VERDICT_ERROR;
			break;
	}
	return v;
}

void dec_bonblocking(void){
	dec_curmax_stats(&bstats.bonblocking);
}
