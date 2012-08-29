#ifndef HANDLER_SFILTER_H
#define HANDLER_SFILTER_H

#ifdef __cplusplus
extern "C" {
#endif

int sfilter_init(void);
int sfilter_destroy(void);

struct sfilter_policy;

typedef enum {
	SFILTER_HANDLERLIST = 501, // "Category Code Definitions", SFCL API doc
	SFILTER_MAXLIST,
} sfilter_category;

struct icap_state;

struct sfilter_policy *sfilter_policy_create(void);
int sfilter_policy_adduri(struct sfilter_policy *,const char *,sfilter_category);
char *sfilter_uri_generate(const struct icap_state *);
int sfilter_uri_query(struct sfilter_policy *,const char *);
void sfilter_policy_destroy(struct sfilter_policy *);

struct icap_state;

int is_https(const struct icap_state *is);

#ifdef __cplusplus
}
#endif

#endif
