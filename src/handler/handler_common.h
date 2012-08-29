#ifndef HANDLER_COMMON__H
#define HANDLER_COMMON__H

#include <libdank/objects/crlfreader.h>
#include <snare/icap/stats.h>
#include "siteinfo.h"

struct ustring;
struct icap_state;

// Flags added into the X-SWEB-Flags HTTP header during REQMOD that we pick up
// again during RESPMOD
#define SWEB_FLAG_WHITELISTED	0x01
#define SWEB_FLAG_NEED_RESPMOD	0x02

typedef struct bassdrum_stats {
	avgmax_stats reppertt;
	curmax_stats bonblocking;
	uintmax_t maldetect,malclean,malerror,maljumbo,malbackuptx,malbypass;
	uintmax_t repper_retries, repper_fail;
	uintmax_t uri_error, header_error, cookie_error, ntlm_error; 
	uintmax_t auth_error, policy_error, pac_error;
	avgmax_stats handler_auth_time, pol_time;
	uintmax_t auth_wfa_cookie, auth_wfa_saml, auth_wfa_native;
	uintmax_t auth_ip, auth_ip_ntlm, auth_ip_ntlm_workaround, auth_ip_cookie;
	uintmax_t auth_port_ntlm, auth_port_ntlm_ie6;
	uintmax_t auth_proxy, auth_cookie, auth_none;
	uintmax_t cookie_profile, port_profile, no_profile;
	uintmax_t vid_size, proxyauth_nonce_down;
} bassdrum_stats;

// Suffix we use for URLs when checking whether our auth cookie has been
// accepted by the browser (cookie gets set, browser gets sent to URL plus
// suffix, we check if the cookie is there and redirect back to the original
// URL w/o the suffix)
#define AUTH_DOM_COOKIE_CHECK_SUFFIX "?scur-swps-cverify"

#define SERVER_HEADER "Server: ICAP server (snare)"CRLF

#define HTML_CONTENT_HEADER "Content-Type: text/html"CRLF

#define OK_HEADERS \
 "HTTP/1.0 200 OK" CRLF \
 SERVER_HEADER \
 HTML_CONTENT_HEADER \
 CRLF

#define ERROR_HEADERS \
 "HTTP/1.0 500 Internal Server Error" CRLF \
 SERVER_HEADER \
 HTML_CONTENT_HEADER \
 CRLF

#define FORBIDDEN_HEADERS \
 "HTTP/1.0 403 Forbidden" CRLF \
 SERVER_HEADER \
 HTML_CONTENT_HEADER \
 CRLF

#define OK_HEADERS_PAC \
 "HTTP/1.0 200 OK" CRLF \
 SERVER_HEADER \
 "Content-Type: application/x-ns-proxy-autoconfig" CRLF \
 CRLF

#define OK_HEADERS_GIF \
 "HTTP/1.0 200 OK" CRLF \
 SERVER_HEADER \
 "Content-Type: image/gif" CRLF \
 CRLF

#define HTML_4_01_TRANSITIONAL \
	"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\n" \
	"	\"http://www.w3.org/TR/html4/loose.dtd\">"

// Template variables for block and warn pages
#define WARN_PAGE_LINK_VAR "%%LINK%%"
#define BLOCKWARN_PAGE_URL_VAR "%%URL%%"
#define BLOCKWARN_PAGE_REP_VAR "%%REPSCORE%%"
#define BLOCKWARN_PAGE_REPCLASS_VAR "%%REPCLASS%%"
#define BLOCKWARN_PAGE_CAT_VAR "%%CATEGORIES%%"
#define BLOCKWARN_PAGE_RULENAME_VAR "%%REASON%%"

// HTTP header that we use to transfer cookie data from REQMOD to RESPMOD for
// NTLM state data. Once we validated the client's NTLM type 3 response in
// REQMOD, we add this HTTP header. It gets picked up in RESPMOD where we then
// set an authentication cookie so that the client doesn't have to go through
// NTLM for that domain anymore.
#define HDR_NTLM_STATE	"X-SWEB-NC:"

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define reqresp_error(is) reqresp_error_msg(is, "Error #" TOSTRING(__LINE__))

extern struct EntityContainer *ec;
extern char *poldata_key;
extern struct bassdrum_stats bstats;
extern unsigned long qid;

char* replace_blockwarn_vars(const char *html, const char *urlcontent, const SiteInfoType *si, const char *rule_name);
int reqresp_redirect(struct icap_state *is, const char *url);
int reqresp_error_msg(struct icap_state *is, const char *msg);
int reqresp_blocked_by_rule(struct icap_state *is, const char *html, const char *url, const SiteInfoType *si);
int reqresp_blocked(struct icap_state *is, const char *html, const char *url, const SiteInfoType *si, const char *reason);
int reqresp_blocked_image(struct icap_state *is);
const char *get_rule_name(const SiteInfoType *si);

// Rewrite with a response, appending a correct Content-Length header. The
// incoming ustring must be a proper HTTP status line, followed by a CRLF,
// followed by zero or more correctly-formed header lines (each terminated by
// a CRLF). The final, header-terminating CRLF must not yet have been added.
int response_rewrite(struct icap_state *,struct ustring *,const char *,size_t)
		__attribute__ ((warn_unused_result));

#endif
