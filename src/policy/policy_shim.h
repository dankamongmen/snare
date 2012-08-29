#ifndef POLICY_SHIM__H
#define POLICY_SHIM__H

#include <stdint.h>
#include "policy_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct EntityContainer;
struct Predicate;
struct icap_state;

#define NTLM_NONE	0
#define NTLM_IDENT	1
#define NTLM_AUTH	2

unsigned int pol_object_count(void);

struct EntityContainer *ec_new(void);
void ec_delete(struct EntityContainer *);
int ec_get_wfa_saml_flag(struct EntityContainer *, unsigned int);
int ec_is_auth_page(struct EntityContainer *, unsigned int eid, const char *);
void ec_get_pol_data_for_ip(struct EntityContainer *,uint32_t,unsigned *,unsigned *, unsigned *, unsigned *, int *, int *);
void ec_get_pol_data_for_uid(struct EntityContainer *,unsigned,unsigned *,unsigned *, unsigned *);
char* ec_get_user_for_uid(struct EntityContainer *, unsigned int);
char* ec_get_netblock_for_ip(struct EntityContainer *, uint32_t);
unsigned int ec_get_uid_by_name(struct EntityContainer *,const char *);
unsigned int ec_get_uid_by_alias(struct EntityContainer *,unsigned int,const char *);
const unsigned char *ec_get_pwhash_by_uid(struct EntityContainer *,unsigned int);
const unsigned char *ec_get_pwntlmhash_by_uid(struct EntityContainer *,unsigned int);
const char *ec_get_pwha1_by_uid(struct EntityContainer *,unsigned int);
ActionType ec_apply_policy_rules(struct EntityContainer *, uint32_t, struct Predicate *, const char **, unsigned int *, int *, int *);
const char *ec_get_rule_name_by_id(struct EntityContainer *,unsigned int);
ActionType ec_apply_policy_url_lists(struct EntityContainer *,uint32_t,const char *);
const char *ec_get_block_page(struct EntityContainer *,uint32_t);
const char *ec_get_warn_page(struct EntityContainer *,uint32_t);
const char *ec_get_pac_file(struct EntityContainer * obj,uint32_t);
const char *ec_get_password(struct EntityContainer * obj,unsigned int);
unsigned ec_get_entity_id(struct EntityContainer *,uint32_t);
int ec_load_policy_file(struct EntityContainer *,const char *);
void ec_print_policy(struct EntityContainer *,unsigned);

struct Predicate *pred_new(void);
void pred_delete(struct Predicate *);
void pred_add_cat(struct Predicate *,CategoryType);
void pred_set_rep(struct Predicate *,int);
void pred_calc_time(struct Predicate *);
void pred_set_uid(struct Predicate *,unsigned int);
void pred_set_hdrs(struct Predicate *, const struct icap_state *);
void pred_print(struct Predicate *);
void pred_set_respmod_flag(struct Predicate *);

#ifdef __cplusplus
}
#endif

#endif
