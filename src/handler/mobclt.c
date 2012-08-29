#include <stdint.h>
#include <libdank/objects/logctx.h>
#include <libdank/objects/lexers.h>
#include <libdank/utils/memlimit.h>
#include <libdank/utils/string.h>
#include "util/misc.h"
#include "mobclt.h"


static void
mobclt_nag(const char* szErrorMsg, int err) {
  nag("msg: [%s], error code: %d\n", szErrorMsg, err);
}

static void*
mobclt_malloc(size_t size) {
  return Malloc("mobile_client", size);
}

static void
mobclt_free(void *ptr) {
  Free(ptr);
}

void mobclt_init(void) {
  authlib_set_error_fxn(mobclt_nag);
  authlib_set_malloc_fxn(mobclt_malloc);
  authlib_set_free_fxn(mobclt_free);
}

int mobclt_check_token(const char *pw, const char *url, const char *ver,
		       const char *user, const char *ts, const char *token,
		       char **decrypted_user) {
  int ret = 0;
  void *pw_bin = NULL;
  size_t pw_len;
  char *userhdr = NULL;
  char *tok = NULL;

  *decrypted_user = NULL;

  pw_bin = hex2bin(pw, &pw_len);
  if(!pw_bin) {
    nag("Converting password failed\n");
    goto cleanup;
  }

  userhdr = Strdup(user);
  if(!userhdr) {
    goto cleanup;
  }

  *decrypted_user = authlib_decrypt_username(pw_bin, pw_len, userhdr);
  if(!*decrypted_user) {
    nag("Error decrypting username\n");
    goto cleanup;
  }
  nag("Decrypted username [%s]\n", *decrypted_user);
  

  tok = authlib_build_token(pw_bin, pw_len, url, *decrypted_user, ts, ver);
  if(!tok) {
    nag("Error building auth token\n");
    goto cleanup;
  }

  if(strcmp(token, tok)) {
    nag("Incorrect token: got [%s], expected [%s]\n", token, tok);
    goto cleanup;
  }

  ret = -1;
 cleanup:
  Free(pw_bin);
  Free(userhdr);
  Free(tok);
  return ret;
}

int mobclt_auth(struct EntityContainer *aec,
		const char *company_id, const char *url, const char *ver,
		const char *user, const char *ts, const char *token,
		unsigned int *uid, unsigned int *pid, unsigned int *eid,
		unsigned int *gid) {
  int ret = 0;
  char *dec_user = NULL;
  uint32_t aeid;
  const char *pw;

  if(strcmp(ver, "2")) {
    nag("Unknown version\n");
    goto cleanup;
  }

  if(lex_u32(&company_id, &aeid)) {
    nag("Error lexing\n");
    goto cleanup;
  }

  pw = ec_get_password(aec, aeid);
  if(!pw) {
    nag("Unable to retrieve customer password\n");
    goto cleanup;
  }
  
  if(!mobclt_check_token(pw, url, ver, user, ts, token, &dec_user)) {
    goto cleanup;
  }

  *uid = ec_get_uid_by_alias(aec, aeid, dec_user);
  if(!*uid) {
    nag("Unknown alias\n");
    goto cleanup;
  }

  ec_get_pol_data_for_uid(aec, *uid, pid, eid, gid);

  if(!*eid) {
    nag("Unable to find policy data\n");
    goto cleanup;
  }

  ret = -1;
 cleanup:
  Free(dec_user);
  return ret;
}
