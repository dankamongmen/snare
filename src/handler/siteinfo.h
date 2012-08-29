#ifndef SITEINFO_H
#define SITEINFO_H

#include <openssl/sha.h>

#define HMAC_KEY_LEN SHA_DIGEST_LENGTH
#define SITEINFOTYPE_INITIALIZER { 0, 0, NULL, 0, 0 }

typedef struct {
  int rep;
  int num_cats;
  uint16_t *cat_array;
  unsigned int rule_id;
  int is_blacklisted;
} SiteInfoType;

void reset_siteinfotype(SiteInfoType *);
char *encode_block_page_data(const char *, const SiteInfoType *, int);
int decode_block_page_data(const char *, char **, SiteInfoType *, int);

#endif
