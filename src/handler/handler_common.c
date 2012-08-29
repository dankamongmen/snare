#include "stringpp.h"
#include "sf_catstrings.h"
#include "handler_common.h"
#include <util/misc.h>
#include <util/sfilter.h>
#include <util/url_escape.h>
#include <handler/handlerconf.h>
#include <libdank/utils/string.h>
#include <libdank/utils/memlimit.h>
#include <libdank/objects/logctx.h>
#include <snare/icap/transmogrify.h>
#include <libdank/objects/objustring.h>
#include <libdank/objects/crlfreader.h>
#include "policy/policy_shim.h"

struct EntityContainer *ec;

char *poldata_key = "kerkjfbl23ivnjsar9i9iwencbjuer8";
unsigned long qid = 0; // current query id

static const unsigned char x_gif[] = {
  0x47, 0x49, 0x46, 0x38, 0x37, 0x61, 0x64, 0x00, 0x64, 0x00, 0x80, 0x02,
  0x00, 0x08, 0x0a, 0x06, 0xfa, 0xfc, 0xf9, 0x2c, 0x00, 0x00, 0x00, 0x00,
  0x64, 0x00, 0x64, 0x00, 0x00, 0x02, 0xfe, 0x84, 0x8f, 0xa1, 0xcb, 0xed,
  0x0f, 0xa3, 0x9c, 0x54, 0xa1, 0x8b, 0x71, 0xdd, 0xbc, 0xfb, 0x95, 0x85,
  0xe1, 0x47, 0x96, 0xa4, 0x88, 0x6a, 0xe6, 0xca, 0x3e, 0xe9, 0x9b, 0xb4,
  0xf2, 0x0a, 0xd7, 0xc6, 0x8c, 0x7b, 0xf6, 0x9e, 0xf7, 0xd3, 0x0e, 0xf4,
  0x09, 0x1b, 0xc0, 0xe2, 0x70, 0x58, 0x4c, 0x1e, 0x7b, 0x4a, 0xe5, 0x52,
  0xe6, 0x0c, 0x44, 0x9f, 0xa5, 0xa9, 0xd4, 0x48, 0x3d, 0x61, 0x89, 0xdb,
  0xec, 0xc6, 0xca, 0x00, 0x7b, 0x21, 0xe2, 0x70, 0x77, 0xec, 0x3a, 0x93,
  0xd5, 0x68, 0x0b, 0x7b, 0x1d, 0x6c, 0x9b, 0xe3, 0x9c, 0x32, 0xd5, 0x2e,
  0xc1, 0x23, 0xdf, 0x15, 0x3d, 0x93, 0xff, 0x05, 0x98, 0xe3, 0xd7, 0x27,
  0x08, 0x65, 0x58, 0x87, 0x68, 0x42, 0xd8, 0xc1, 0xf8, 0xe1, 0xd8, 0xa8,
  0x18, 0x49, 0xe7, 0x03, 0x49, 0x61, 0xf9, 0x28, 0xf9, 0xa3, 0xb9, 0xc8,
  0x99, 0x46, 0xf9, 0x84, 0x39, 0xc7, 0x83, 0x26, 0x7a, 0x05, 0xea, 0x85,
  0x69, 0x7a, 0x88, 0x9a, 0xe7, 0xf9, 0xd7, 0xfa, 0x49, 0x2a, 0xc7, 0x15,
  0x3b, 0x6a, 0x43, 0x0b, 0x37, 0x2b, 0x8b, 0x9b, 0xab, 0xdb, 0xeb, 0xb0,
  0xba, 0x04, 0x26, 0x1c, 0xda, 0x55, 0x7c, 0x87, 0x85, 0x9c, 0x95, 0xb4,
  0x9c, 0xda, 0x0c, 0xec, 0xab, 0x03, 0xfd, 0x22, 0xdd, 0x49, 0x3d, 0x62,
  0x7d, 0x8d, 0x1d, 0xa3, 0xbd, 0xcd, 0xed, 0xdd, 0xc2, 0x7d, 0x13, 0x2e,
  0x8e, 0x5d, 0x3e, 0x43, 0x8d, 0x8e, 0xd3, 0xbc, 0xce, 0xee, 0xbc, 0xae,
  0xee, 0x4e, 0x73, 0x3e, 0xaf, 0x05, 0x6e, 0x3f, 0x39, 0x9e, 0x1f, 0x38,
  0x7e, 0xc0, 0xbf, 0xc9, 0x5f, 0x37, 0x80, 0xb5, 0x04, 0x0e, 0x24, 0x78,
  0xca, 0xe0, 0x05, 0x84, 0x6e, 0x14, 0x66, 0x40, 0xe8, 0x04, 0xde, 0x1e,
  0x4a, 0x12, 0x61, 0xed, 0x6a, 0x78, 0x31, 0x5c, 0x99, 0x8c, 0x8a, 0xe6,
  0x6c, 0x25, 0x8c, 0x66, 0xcd, 0x0f, 0xc7, 0x7b, 0x19, 0x7f, 0xd5, 0x08,
  0xa9, 0x69, 0x64, 0xbf, 0x92, 0x01, 0x59, 0x1a, 0xf3, 0xe8, 0x0a, 0x66,
  0xa5, 0x57, 0x20, 0x68, 0x92, 0x04, 0x79, 0xf3, 0x64, 0x32, 0x99, 0x2b,
  0x71, 0x5a, 0xf4, 0xf9, 0x4d, 0xa7, 0x10, 0x8e, 0x23, 0x55, 0x56, 0x54,
  0x89, 0x11, 0x68, 0x4e, 0x18, 0x3b, 0x5d, 0xea, 0x53, 0xfa, 0x53, 0x68,
  0x15, 0x9b, 0x4b, 0xab, 0x4d, 0xe5, 0x19, 0x95, 0x69, 0x26, 0xac, 0x33,
  0xb9, 0x26, 0x95, 0x2a, 0xc7, 0x11, 0xd2, 0x44, 0x3c, 0xc7, 0x3e, 0x05,
  0x1b, 0x8c, 0x6a, 0x57, 0x97, 0x66, 0xab, 0xa6, 0xe0, 0x85, 0x56, 0xe3,
  0x99, 0xb6, 0xf4, 0xe8, 0xd0, 0x65, 0xd1, 0x44, 0xed, 0x18, 0x87, 0x0f,
  0x19, 0x7e, 0x74, 0xe8, 0xb7, 0x26, 0xdf, 0xc0, 0xb7, 0xfc, 0x11, 0x2e,
  0xb8, 0xef, 0x30, 0x62, 0x79, 0x8a, 0x17, 0xdf, 0x7d, 0x06, 0xad, 0x71,
  0x4c, 0xbd, 0xf6, 0x50, 0x14, 0x00, 0x00, 0x3b
};

// Rewrite with a response, appending a correct Content-Length header. The
// incoming ustring must be a proper HTTP status line, followed by a CRLF,
// followed by zero or more correctly-formed header lines (each terminated by
// a CRLF). The final, header-terminating CRLF must not yet have been added.
int response_rewrite(struct icap_state *is,ustring *u,const char *body,size_t bodylen){
	if(printUString(u,"Content-Length: %zu" CRLF CRLF,bodylen) < 0){
		return -1;
	}
	return icap_response_rewrite(is,u->string,u->current,body,bodylen);
}

char* replace_blockwarn_vars(const char *html, const char *urlcontent, const SiteInfoType *si, const char *rule_name) {
   char *html2 = NULL;
   char *html3 = NULL;
   char *rethtml = NULL, *escurl = NULL;
   ustring us = USTRING_INITIALIZER;
   char *repclass;

   // Escape the URL so that it can be used inside html
   escurl = XssEscapeDup(urlcontent);
   if(!escurl) {
     goto cleanup;
   }

   if(si->rep < 0) {
     repclass = "Trusted";
   } else if(si->rep < 15) {
     repclass = "Neutral";
   } else if(si->rep < 30) {
     repclass = "Unverified";
   } else if(si->rep < 50) {
     repclass = "Suspicious";
   } else {
     repclass = "Malicious";
   }
   
   // Replace the URL var with the actual URL
   html2 = find_and_replace_all(html, BLOCKWARN_PAGE_URL_VAR, escurl);
   if(!html2) {
     goto cleanup;
   }
   
   // Convert reputation to string and replace reputation var with it
   if(printUString(&us, "%d", si->rep) < 0) {
     goto cleanup;
   }
   html3 = find_and_replace_all(html2, BLOCKWARN_PAGE_REP_VAR, us.string);
   if(!html3) {
     goto cleanup;
   }
   Free(html2);
   html2 = NULL;
   
   // Reputation class var
   html2 = find_and_replace_all(html3, BLOCKWARN_PAGE_REPCLASS_VAR, repclass);
   if(!html2) {
     goto cleanup;
   }
   Free(html3);
   html3 = NULL;
   
   // Categories var
   reset_ustring(&us);
   if(si->num_cats) {
     int i;
     if(printUString(&us, "%s", get_category_name(si->cat_array[0])) < 0) {
       goto cleanup;
     }
     for(i = 1; i < si->num_cats; i++) {
       if(printUString(&us, ", %s", get_category_name(si->cat_array[i])) < 0) {
	 goto cleanup;
       }
     }
   } else {
     if(printUString(&us, "None") < 0) {
       goto cleanup;
     }
   }
   html3 = find_and_replace_all(html2, BLOCKWARN_PAGE_CAT_VAR, us.string);
   if(!html3) {
     goto cleanup;
   }
   Free(html2);
   html2 = NULL;

   html2 = find_and_replace_all(html3, BLOCKWARN_PAGE_RULENAME_VAR, rule_name);
   if(!html2) {
     goto cleanup;
   }
   Free(html3);
   html3 = NULL;

   rethtml = Strdup(html2);

 cleanup:
   Free(escurl);
   Free(html2);
   Free(html3);
   return rethtml;
}

int reqresp_redirect(struct icap_state *is, const char *url) {
  ustring respbody = USTRING_INITIALIZER;
  ustring resphdr = USTRING_INITIALIZER;
  char *escaped_url = NULL;

  nag("Writing HTTP 307 Temporary Redirect\n");
  if((escaped_url = XssEscapeDup(url)) == NULL){
  	goto err;
  }

  if(printUString(&resphdr,
	   "HTTP/1.1 307 Temporary Redirect" CRLF
	   "Location: %s" CRLF
	   SERVER_HEADER HTML_CONTENT_HEADER, url) < 0){
	  goto err;
  }

  if(printUString(&respbody,
	   "<html><body><h1>Found</h1>"
	   "<p><a href=\"%s\">Click here</a> if automatic redirection to %s fails.</p>"
	   "</body></html>",
	   url, escaped_url
	   ) < 0){
	  goto err;
  }
  if(response_rewrite(is, &resphdr, respbody.string, respbody.current)){
	goto err;
  }
  reset_ustring(&respbody);
  reset_ustring(&resphdr);
  Free(escaped_url);
  return 0;

err:
  reset_ustring(&resphdr);
  reset_ustring(&respbody);
  Free(escaped_url);
  return reqresp_error(is);
}

int reqresp_error_msg(struct icap_state *is, const char *msg) {
  const char *response_hdr = ERROR_HEADERS;
  ustring response_body = USTRING_INITIALIZER;
  if(printUString(&response_body, "<html><body><h1>Error</h1><p>An error occured in the Policy Manager:</p><pre>%s</pre></body></html>", msg) < 0) {
    reset_ustring(&response_body);
    return -1;
  }
  if(icap_response_rewrite(is, response_hdr, strlen(response_hdr), response_body.string, response_body.current)){
    reset_ustring(&response_body);
    return -1;
  }
  reset_ustring(&response_body);
  return 0;
}

int reqresp_blocked_by_rule(struct icap_state *is, const char *html, const char *url, const SiteInfoType *si) {
  const char *rule_name;
  rule_name = get_rule_name(si);
  return reqresp_blocked(is, html, url, si, rule_name);
}

int reqresp_blocked(struct icap_state *is, const char *html, const char *url, const SiteInfoType *si, const char *reason) {
  int ret;

  if(is_https(is)) {
    char *blockuri;
    nag("Blocking on HTTPS CONNECT\n");
    if((blockuri = get_blockuri())) {
      ustring us = USTRING_INITIALIZER;
      char *data = encode_block_page_data(url, si, -1);
      if(!data) {
	ret = reqresp_error(is);
      } else {
	if(printUString(&us, "%s%s", blockuri, data) < 0) {
	  ret = reqresp_error(is);
	} else {
	  ret = reqresp_redirect(is, us.string);
	}
	Free(data);
      }
      reset_ustring(&us);
      Free(blockuri);
    } else {
      // No block page URI => send back error page. Well, the client won't see
      // this since it causes the behavior described in Bug 311, but this is
      // better than nothing...
      ret = reqresp_error(is);
    }
  } else {
    const char *response_hdr = OK_HEADERS;
    char *rethtml = NULL;

    ret = -1;

    // const char *html can be NULL
    if(!html) {
      reqresp_error_msg(is, "No block page configured");
      goto cleanup;
    }

    rethtml = replace_blockwarn_vars(html, url, si, reason);
    if(!rethtml) {
      reqresp_error_msg(is, "Error preparing block page");
      goto cleanup;
    }

    ret = icap_response_rewrite(is, response_hdr, strlen(response_hdr), rethtml, strlen(rethtml));
  cleanup:
    Free(rethtml);
  }
  return ret;
}

int reqresp_blocked_image(struct icap_state *is) {
  return icap_response_rewrite(is, OK_HEADERS_GIF, strlen(OK_HEADERS_GIF), (const char*)x_gif, sizeof(x_gif));
}

const char *get_rule_name(const SiteInfoType *si) {
  const char *rule_name;
  if(si->is_blacklisted) {
    rule_name = "Blocklisted";
  } else {
    rule_name = ec_get_rule_name_by_id(ec, si->rule_id);
    if(!rule_name) {
      nag("Failed to get a rule name\n");
      rule_name = "--";
    }
  }
  return rule_name;
}
