#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <libdank/utils/hex.h>
#include <libdank/utils/memlimit.h>
#include <libdank/utils/string.h>
#include <libdank/objects/logctx.h>

#include "siteinfo.h"

extern unsigned char internal_hmac_key[HMAC_KEY_LEN];

void reset_siteinfotype(SiteInfoType *si) {
  SiteInfoType csi = SITEINFOTYPE_INITIALIZER;
  Free(si->cat_array);
  *si = csi;
}

int decode_block_page_data(const char *data, char **url, SiteInfoType *si, int check_hmac) {
  int arep, abl, ret = 0;
  unsigned int anum_cats, i, arid;
  uint16_t *acat_array = NULL;
  char *aurl = NULL, *adata = NULL, *s, *t, *ep;
  size_t len;
  uint8_t hmac_buf[HMAC_KEY_LEN], hmac_buf_ref[HMAC_KEY_LEN];
  unsigned int data_len;

  s = adata = Strdup(data);
  if(!adata) {
    return 0;
  }

  // get rule id
  t = strsep(&s, ",");
  if(!t) {
    goto cleanup;
  }
  arid = (unsigned int)strtoul(t, &ep, 16);

  // get is_blacklisted
  t = strsep(&s, ",");
  if(!t) {
    goto cleanup;
  }
  abl = atoi(t);

  // get rep
  t = strsep(&s, ",");
  if(!t) {
    goto cleanup;
  }
  arep = atoi(t);

  // get number of categories
  t = strsep(&s, ",");
  if(!t) {
    goto cleanup;
  }
  anum_cats = (unsigned int)strtoul(t, &ep, 16);

  // get category set
  if(anum_cats) {
    acat_array = Malloc("acat_array", anum_cats * sizeof(uint16_t));
    if(!acat_array) {
      goto cleanup;
    }
    for(i = 0; i < anum_cats; i++) {
      t = strsep(&s, ",");
      if(!t) {
	goto cleanup;
      }
      acat_array[i] = (uint16_t)strtoul(t, &ep, 16);
    }
  }

  // get URL
  t = strsep(&s, ",");
  if(!t) {
    goto cleanup;
  }
  len = strlen(t);
  aurl = Malloc("aurl", len / 2 + 1); // +1 for string termination
  if(!aurl) {
    goto cleanup;
  }
  if(!hextoascii(t, (unsigned char *)aurl, EOF, len / 2)) {
    bitch("URL conversion failed\n");
    goto cleanup;
  }
  aurl[len / 2] = '\0';

  // get HMAC
  if(check_hmac) {
    t = strsep(&s, ",");
    if(!t) {
      goto cleanup;
    }
    data_len = t - adata;
    if(!hextoascii(t, hmac_buf, EOF, sizeof(hmac_buf))) {
      bitch("HMAC truncated\n");
      goto cleanup;
    }

    HMAC(EVP_sha1(), internal_hmac_key, sizeof(internal_hmac_key),
	 (const unsigned char *)data, data_len, hmac_buf_ref, 0);
    if(memcmp(hmac_buf, hmac_buf_ref, sizeof(hmac_buf))) {
      // hmac is incorrect
      bitch("HMAC doesn't match\n");
      goto cleanup;
    }
  }

  // copy final values
  if(url) {
    *url = aurl;
  }
  si->cat_array = acat_array;
  si->rep = arep;
  si->num_cats = anum_cats;
  si->rule_id = arid;
  si->is_blacklisted = abl;
  ret = 1;

 cleanup:
  Free(adata);
  if(!ret) {
    Free(aurl);
    Free(acat_array);
  }
  return ret;
}

char* encode_block_page_data(const char *url, const SiteInfoType *si, int gen_hmac) {
  ustring us = USTRING_INITIALIZER;
  char *ret, *encurl = NULL;
  int i;
  uint8_t hmac_buf[HMAC_KEY_LEN];
  char hex_hmac[2 * sizeof(hmac_buf) + 1];

  // rule_id, is_blacklisted, rep, and number of categories
  if(printUString(&us, "%x,%d,%d,%x,", si->rule_id, si->is_blacklisted, si->rep, si->num_cats) < 0) {
    return NULL;
  }

  // categories
  for(i = 0; i < si->num_cats; i++) {
    if(printUString(&us, "%x,", si->cat_array[i]) < 0) {
      reset_ustring(&us);
      return NULL;
    }
  }

  // url
  if(url) {
    encurl = Malloc("encurl", 2 * strlen(url) + 1);
    if(!encurl) {
      reset_ustring(&us);
      return NULL;
    }

    asciitohex(url, encurl, EOF, strlen(url));
    encurl[strlen(url)] = '\0';
    if(printUString(&us, "%s,", encurl) < 0) {
      reset_ustring(&us);
      Free(encurl);
      return NULL;
    }
    Free(encurl);
  } else {
    if(printUString(&us, "00,") < 0) {
      reset_ustring(&us);
      Free(encurl);
      return NULL;
    }
  }

  if(gen_hmac) {
    HMAC(EVP_sha1(), internal_hmac_key, sizeof(internal_hmac_key),
	 (const unsigned char*)us.string, us.current, hmac_buf, 0);
    asciitohex(hmac_buf, hex_hmac, EOF, sizeof(hmac_buf));
    
    if(printUString(&us, "%s", hex_hmac) < 0) {
      reset_ustring(&us);
      return NULL;
    }
  }

  ret = Strdup(us.string);
  reset_ustring(&us);
  return ret;
}
