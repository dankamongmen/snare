#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <snare/poller.h>
#include <snare/oqueue.h>
#include <snare/server.h>
#include <snare/threads.h>
#include <libbon/libbon.h>
#include <handler/handler.h>
#include <handler/respmod.h>
#include <snare/icap/stats.h>
#include <snare/icap/request.h>
#include <snare/icap/response.h>
#include <handler/handlerconf.h>
#include <libdank/utils/string.h>
#include <libdank/utils/syswrap.h>
#include <libdank/utils/memlimit.h>
#include <libdank/objects/lexers.h>
#include <snare/icap/transmogrify.h>
#include <libdank/objects/crlfreader.h>
#include "ntlm.h"
#include "param.h"
#include "mobclt.h"
#include "handler_common.h"
#include "policy/policy_shim.h"

static struct libbon_bridge *bonbridge = NULL;

typedef struct {
  unsigned int pid;
} pol_data;

// We can definitely replace the floor hack via, for instance, not scanning
// until one second after we start receiving data. This is only true, however,
// if we're using the floor for purposes other thank working around libscanm
// false-positive issues.
#define ARBITRARY_LIBBON_FLOOR_HACK (1024 * 1024) // FIXME
#define ARBITRARY_LIBBON_CEILING_HACK (1024 * 1024 * 8) // FIXME

static int
extract_reqmod_data(const char *data, SiteInfoType *si, unsigned int *eid,
		    unsigned int *pid, unsigned int *uid, unsigned int *gid) {
  int ret = -1;
  char *enc = NULL, *dec = NULL, *dummy_url = NULL;
  ParamNodeType *pl = NULL;
  const char *s, *bldata;
  size_t len_output;
  uint32_t _eid, _pid, _uid, _gid;

  enc = Strdup(data);
  if(!enc) {
    goto cleanup;
  }

  nag("Processing policy data header: %s\n", enc);

  dec = (char *)decrypt_data(poldata_key, strlen(poldata_key),
			     enc, &len_output);
  if(!dec) {
    goto cleanup;
  }
  nag("Decrypted: %s\n", dec);

  pl = parse_params(dec, "&");

#define GET_PARAM_VAL(param) \
  if(!(s = get_param_value(pl, #param, 0))) { \
    nag(#param " param not found\n"); \
    goto cleanup; \
  } \
  if(lex_u32(&s, &_ ## param)) { \
    nag("Error lexing " #param " [%s]\n", s); \
    goto cleanup; \
  }

  GET_PARAM_VAL(eid)
  GET_PARAM_VAL(pid)
  GET_PARAM_VAL(uid)
  GET_PARAM_VAL(gid)

#undef GET_PARAM_VAL

  // si
  bldata = get_param_value(pl, "bldata", 0);
  if(!decode_block_page_data(bldata, &dummy_url, si, 0)) { // returns false on error... argh!
    nag("Error decoding meta data\n");
    goto cleanup; 
  }

  *eid = _eid;
  *pid = _pid;
  *uid = _uid;
  *gid = _gid;

  ret = 0;
 cleanup:
  Free(dummy_url);
  Free(enc);
  Free(dec);
  delete_param_list(pl);
  return ret;
}

static int
repopulate_predicate(struct Predicate *p, struct icap_state *is, SiteInfoType *si, unsigned int uid,
		     ustring *xattr) {
  ssize_t i;

  pred_set_rep(p, si->rep);
  if(printUString(xattr, "; rep: %d", si->rep) < 0) {
    return -1;
  }  
  if(printUString(xattr, "; cat:") < 0) {
    return -1;
  }
  for(i = 0; i < si->num_cats; ++i) {
    if(printUString(xattr, " %u", si->cat_array[i]) < 0) {
      return -1;
    }
    pred_add_cat(p, si->cat_array[i]);
  }
  pred_set_uid(p, uid);
  pred_set_respmod_flag(p);	// Indicate that we're in RESPMOD now -- all rules can be evaluated
  pred_set_hdrs(p, is);		// Copy header fields from icap_state into header map
  
  return 0;
}

static int
antimalware_rewrite(icap_state *is,unsigned probability,const char *name){
#define HDRTAG "X-LOG-amww: "
	char hdr[strlen(HDRTAG) + SCANMAPI_MAX_STRLEN] = HDRTAG;
	unsigned int eid = 0, pid = 0, uid = 0, gid = 0;
	SiteInfoType si = SITEINFOTYPE_INITIALIZER;

	inc_maldetect();
	nag("Rewriting based off probability %u name %s\n",probability,name);
	strcpy(hdr + strlen(HDRTAG),name);
	if(add_icap_respheader(is,hdr)){
		return -1;
	}

	if(is->encaps.http.x_sweb_data) {
	  if(extract_reqmod_data(is->encaps.http.x_sweb_data, &si, &eid, &pid, &uid, &gid)) {
	    nag("Error extracting reqmod data\n");
	    return reqresp_error_msg(is, "Malware detected, but unable to parse policy data\n");
	  }
	} else {
	  bitch("No data header\n");
	}

	if(!pid) {
	  return reqresp_error_msg(is, "Malware detected, but no policy data available\n");
	}
	
	return reqresp_blocked(is, ec_get_block_page(ec, pid), is->encaps.http.rawuri, &si, name);
#undef HDRTAG
}

static int
piperx_callback(struct poller *p __attribute__ ((unused)),struct pollfd_state *pfd){
	// FIXME when pfd->state goes to void *, remove this cast
	struct libbon_bridge *lbr = (struct libbon_bridge *)pfd->state;
	struct oqueue_key *okey;
	libbon_result lres;

	if(libbon_rx_callback(lbr)){
		invalidate_libbon_wfd(lbr);
		return -1;
	}
	while( (okey = libbon_pop_analysis(lbr,&lres)) ){
		verdict v = VERDICT_SKIP;

		dec_bonblocking();
		if(okey->cbarg){
			struct icap_state *is = get_pfd_icap(okey->cbarg);

			if(lres.result == 0){
				// If probability and result are both 0, bonware
				// needed more data before it could pronounce a
				// clean verdict -- but no malware was found.
				// Thus, trickle through this point.
				if(lres.probability == 0){
					if(icap_trickle_payload(is,okey->allows_tx_through) == 0){
						v = VERDICT_TRICKLE;
					} // otherwise, we'll send SKIP
				}else{
					v = VERDICT_DONE;
					inc_malclean();
				}
			}else if(lres.result < 0){
				v = VERDICT_ERROR;
				inc_malerror();
			}else{
				if(antimalware_rewrite(is,lres.probability,lres.name)){
					v = VERDICT_ERROR;
					inc_malerror();
				}else{
					v = VERDICT_DONE;
				}
			}
		}
		// Don't error out here; the libbon fd oughtn't be purged just
		// because we had a verdict error.
		oqueue_passverdict_internal(&okey,v);
	}
	return 0;
}

static int
pipetx_callback(struct poller *p __attribute__ ((unused)),struct pollfd_state *pfd){
	struct libbon_bridge *lbr = (struct libbon_bridge *)pfd->state;

	if(libbon_tx_available(lbr)){
		if(errno != EAGAIN){
			inc_malbackuptx();
			return -1;
		}
	}
	return 0;
}

static int
bonbridge_sigchld_fxn(struct poller *p __attribute__ ((unused)),struct pollfd_state *pfd){
	if(pfd){
		bitch("pfd at %p\n",pfd);
		return -1;
	}
	return sigchld_libbon_bridge(bonbridge);
}

static int
stringize_pipe(ustring *u,const struct pollfd_state *pfd __attribute__ ((unused))){
	if(printUString(u,"<libbon/>") < 0){
		return -1;
	}
	return 0;
}

static int
setup_bonware_poller(struct libbon_bridge *lbr){
	struct pollfd_submission psub;
	pid_t childpid;
	int fd;

	childpid = get_libbon_pid(lbr);
	if(add_child_to_pollqueue(snarepoller,childpid,bonbridge_sigchld_fxn)){
		return -1;
	}
	// FIXME failures from here on out leave crap in the poller
	memset(&psub,0,sizeof(psub));
	fd = get_libbon_fd(lbr);
	nag("Got fd %d from libbon\n",fd);
	if(fd < 0){
		return -1;
	}
	psub.fd = fd;
	psub.state = lbr;
	psub.rxfxn = piperx_callback;
	psub.txfxn = pipetx_callback;
	psub.strfxn = stringize_pipe;
	if(add_fd_to_pollqueue(snarepoller,&psub,NULL,0)){
		return -1;
	}
	return 0;
}

int init_bassdrum_respmod(void){
	char *bontool_path,*bontool_sigs;

	bontool_path = get_bontool_path();
	bontool_sigs = get_bontool_sigs();
	if(bontool_path && bontool_sigs){
		if((bonbridge = init_libbon_bridge(bontool_path,bontool_sigs,NULL)) == NULL){
			Free(bontool_path);
			Free(bontool_sigs);
			return -1;
		}
		if(setup_bonware_poller(bonbridge)){ // FIXME how to clean it?
			Free(bontool_path);
			Free(bontool_sigs);
			return -1;
		}
	}
	Free(bontool_path);
	Free(bontool_sigs);
	return 0;
}

int stop_bassdrum_respmod(void){
	int ret = 0;

	if(bonbridge){
		nag("Killing anti-malware bridge\n");
		ret |= stop_libbon_bridge(bonbridge);
		bonbridge = NULL;
	}
	return ret;
}

typedef struct handler_state {
	time_t last_scan_time;
} handler_state;

static int
is_image(icap_state *is) {
  const char *img = "image/";
  if(is->encaps.http.resp_contenttype) {
    if(strncmp(is->encaps.http.resp_contenttype, img, strlen(img)) == 0) {
      return -1;
    }
  }
  return 0;
}

// returns -1 on error, 0 to continue respmod, 1 if rewrite occurred
static int
resp_eval_policy_rules(struct icap_state *is) {
  int ret = -1;
  unsigned int eid = 0, pid = 0, uid = 0, gid = 0;
  SiteInfoType si = SITEINFOTYPE_INITIALIZER;
  struct Predicate *p = NULL;
  int dummy_force_safe_search, dummy_bypass_anti_malware;
  const char *alert_email_addr;
  ActionType action;
  ustring xattr = USTRING_INITIALIZER;

  p = pred_new();

  if(!p) {
    nag("Can't create predicate\n");
    goto cleanup;
  }

  if(!is->encaps.http.x_sweb_data) {
    nag("Missing sweb data header\n");
    goto cleanup;
  }

  if(extract_reqmod_data(is->encaps.http.x_sweb_data, &si, &eid, &pid, &uid, &gid)) {
    nag("Error extracting reqmod data\n");
    goto cleanup;
  }

  if(printUString(&xattr, "X-Attribute: qid: %lu; eid: %u; uid: %u; gid: %u",
		  qid++, eid, uid, gid) < 0) {
    goto cleanup;
  }
  
  if(repopulate_predicate(p, is, &si, uid, &xattr)) {
    goto cleanup;
  }

  // Note that this call will also trigger the calculation of some additional
  // data in the predicate, e.g. the quota flag and the time/date information
  action = ec_apply_policy_rules(ec, pid, p, &alert_email_addr, &si.rule_id,
				 &dummy_force_safe_search, &dummy_bypass_anti_malware);

  switch(action) {
  case ACT_WARN: // xxx fixme
    nag("RESPMOD warn action translated to block\n");
    // no break here, continue with block
  case ACT_BLOCK:
    nag("RESPMOD block\n");
    if(is_image(is)) {
      reqresp_blocked_image(is);
    } else {
      reqresp_blocked_by_rule(is, ec_get_block_page(ec, pid), is->encaps.http.rawuri, &si);
    }
    if(printUString(&xattr, "; action: block") < 0) {
      goto cleanup;
    }
    ret = 1;
    goto cleanup;
  case ACT_ALLOW:
    if(printUString(&xattr, "; action: allow") < 0) {
      goto cleanup;
    }
    break;
  default:
    nag("Unexpected RESPMOD action\n");
    goto cleanup;
  }

  ret = 0;
 cleanup:
  if(ret != -1) {
    nag("%s\n", xattr.string);
    if(add_icap_respheader(is, xattr.string)) {
      nag("Couldn't add X-Attribute\n");
      ret = -1;
    }
  }
  reset_ustring(&xattr);
  pred_delete(p);
  return ret;
}

verdict respmod_handler(struct oqueue_key *oqk,icap_callback_e cbtype){
	int complete = 1;

	if(bonbridge == NULL){
		nag("No body analysis configured for %d\n",oqk->cbarg->pfd.fd);
		return VERDICT_DONE;
	}
	switch(cbtype){
	case ICAP_CALLBACK_INCOMPLETE_BODY: {
		if(oqueue_usedlen(oqk) < ARBITRARY_LIBBON_FLOOR_HACK){
			return VERDICT_SKIP;
		}
		complete = 0;
		// Intentional fall-through!
	} case ICAP_CALLBACK_BODY: { // Always scan once complete, even runts
		// nag("cbtype %d len %zu\n",cbtype,oqueue_usedlen(oqk));
		if(oqueue_usedlen(oqk) >= ARBITRARY_LIBBON_CEILING_HACK){
			nag("Not analyzing %zub body\n",oqueue_usedlen(oqk));
			inc_maljumbo();
			return VERDICT_DONE;
		}
		if(oqueue_usedlen(oqk) == 0){
			return VERDICT_DONE;
		}
		nag("analyzing %zub (cbtype %d) at %s, complete: %d\n",
				oqueue_usedlen(oqk),cbtype,oqk->fname,complete);
		errno = 0;
		if(libbon_analyze(bonbridge,oqk->fname,oqueue_const_ptrto(oqk,0),
					oqueue_usedlen(oqk),complete,oqk)){
			if(errno == EAGAIN){
				inc_malbackuptx();
			}
			break;
		}
		return VERDICT_COUNT;
		break;
	} case ICAP_CALLBACK_HEADERS:{
		struct icap_state *is = get_pfd_icap(oqk->cbarg);
		const char *xnc = is->encaps.http.x_sweb_nc;
		const char *xfl = is->encaps.http.x_sweb_flags;

		if(xnc) {
		  if(set_ntlm_cookies(is, xnc)) {
		    nag("Failed to set cookies based on encrypted data [%s]\n", xnc);
		    return VERDICT_ERROR;
		  }
		}
		if(xfl){
		  uint32_t flags;
		  if(lex_u32(&xfl, &flags)) {
		    bitch("Lexing flags failed\n");
		    return VERDICT_ERROR;
		  }
		  nag("Flags: %u\n", (unsigned)flags);
		  if(flags & SWEB_FLAG_NEED_RESPMOD) {
		    int res;
		    nag("Evaluating policy rules in RESPMOD\n");
		    res = resp_eval_policy_rules(is);
		    if(res == -1) {
		      nag("An error occurred while evaluating rules\n");
		      return VERDICT_ERROR;
		    } else if (res == 1) {
		      nag("Rewrite, done\n");
		      return VERDICT_DONE;
		    }
		    nag("Continuing RESPMOD after rule evaluation\n");
		  }
		  if(flags & SWEB_FLAG_WHITELISTED) {
		    nag("Whitelisting active\n");
		    inc_malbypass();
		    return VERDICT_DONE;
		  }
		}
		return VERDICT_SKIP;
		break;
	} default:
		bitch("Unhandled cbtype (%d)\n",cbtype);
	}
	return VERDICT_ERROR; // Handle any exit as an error.
}

int antimalware_update_wrapper(struct cmd_state *cs __attribute__ ((unused))){
	int ret = 0;

	if(block_poller(snarepoller)){
		return -1;
	}
	ret = reconfigure_libbon_bridge(bonbridge);
	invalidate_istag();
	ret |= unblock_poller(snarepoller);
	return ret;
}

int stringize_antimalware_version(ustring *u){
	int ret = 0;

	if(bonbridge){
		ret = libbon_stringize_version(u,bonbridge);
	}
	return ret;
}
