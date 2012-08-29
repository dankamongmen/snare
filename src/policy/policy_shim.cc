#include <new>
#include <iostream>
#include <libdank/objects/logctx.h>
#include "policy_shim.h"
#include "policy.h"
#include "config_parser.h"

unsigned int pol_object_count() {
  return PolObject::GetCount();
}

struct EntityContainer *ec_new(){
	try{
		return new EntityContainer();
	}catch(...){
		bitch("Couldn't create an entity container\n");
		return 0;
	}
}

void ec_delete(struct EntityContainer *obj){
	delete obj;
}

int ec_get_wfa_saml_flag(struct EntityContainer *ec, unsigned int eid) {
  return ec->GetWfaSamlFlag(eid) ? -1 : 0;
}

int ec_is_auth_page(struct EntityContainer *ec, unsigned int eid, const char *url) {
  return ec->IsAuthPage(eid, url) ? -1 : 0;
}

void ec_get_pol_data_for_ip(struct EntityContainer *ec, uint32_t ip,
			    unsigned *uid, unsigned *pid, unsigned *eid, unsigned *gid,
			    int *use_ntlm, int *use_cookieauth) {
  bool _use_ntlm_ident, _use_ntlm_auth, _use_cookieauth;
  ec->GetPolDataForIP(ip, uid, pid, eid, gid, &_use_ntlm_ident, &_use_ntlm_auth,  &_use_cookieauth);
  if(_use_ntlm_auth) {
    *use_ntlm = NTLM_AUTH;
  } else if(_use_ntlm_ident) {
    *use_ntlm = NTLM_IDENT;
  } else {
    *use_ntlm = NTLM_NONE;
  }
  *use_cookieauth = _use_cookieauth ? -1 : 0;
}

void ec_get_pol_data_for_uid(struct EntityContainer *ec, unsigned uid,
			    unsigned *pid, unsigned *eid, unsigned *gid){
	ec->GetPolDataForUid(uid, pid, eid, gid);
}

char* ec_get_user_for_uid(struct EntityContainer *ec, unsigned int uid){
    return ec->GetUserForUid(uid);
}

char* ec_get_netblock_for_ip(struct EntityContainer *ec, uint32_t ip){
    return ec->GetNetblockForIP(ip);
}

unsigned int ec_get_uid_by_name(struct EntityContainer *ec,const char *uname) {
  User *u = ec->GetUserContainer().Get(uname);
  if(u) {
    return u->GetId();
  }
  return 0;
}

unsigned int ec_get_uid_by_alias(struct EntityContainer *ec,unsigned int eid,const char *alias) {
  return ec->GetUidForAlias(eid, alias);
}

const unsigned char *ec_get_pwhash_by_uid(struct EntityContainer *ec,unsigned int uid) {
  User *u = dynamic_cast<User*>(ec->GetUserContainer().Get(uid));
  if(u) {
    return u->GetPasswordHash();
  }
  return 0;
}

const unsigned char *ec_get_pwntlmhash_by_uid(struct EntityContainer *ec,unsigned int uid) {
  User *u = dynamic_cast<User*>(ec->GetUserContainer().Get(uid));
  if(u) {
    return u->GetPasswordNtlmHash();
  }
  return 0;
}

const char *ec_get_pwha1_by_uid(struct EntityContainer *ec,unsigned int uid) {
  User *u = dynamic_cast<User*>(ec->GetUserContainer().Get(uid));
  if(u) {
    return u->GetPasswordHA1();
  }
  return 0;
}

ActionType ec_apply_policy_rules(struct EntityContainer *ec, unsigned pid, struct Predicate *p,
				 const char **alert_email_addr, unsigned int *rule_id,
				 int *force_safe_search, int *bypass_anti_malware){
	ActionType act;
	bool fss, bam;
	*force_safe_search = 0;
	*bypass_anti_malware = 0;
	try{
		act = ec->ApplyPolicyRules(pid, *p, alert_email_addr, rule_id, fss, bam);
		if(fss) {
		  *force_safe_search = 1;
		}
		if(bam) {
		  *bypass_anti_malware = 1;
		}
		return act;
	}catch(...){
		return ACT_ERROR;
	}
}

const char *ec_get_rule_name_by_id(struct EntityContainer *ec, unsigned int rule_id) {
  if(rule_id) {
    Rule *r = dynamic_cast<Rule*>(ec->GetRuleContainer().Get(rule_id));
    if(r) {
      return r->GetRuleName();
    }
    return 0;
  }
  return "Default rule";
}

ActionType ec_apply_policy_url_lists(struct EntityContainer *ec,uint32_t ip,
						const char *uri){
	try{
		return ec->ApplyPolicyUrlLists(ip,uri);
	}catch(...){
		return ACT_ERROR;
	}
}

int ec_load_policy_file(struct EntityContainer *ec,const char *fn){
	try{
		if(load_policy_file(fn,ec)){
			return -1;
		}
	} catch(PolEx &px) {
		bitch("Caught an exception: %s\n", px.what());
		return -1;
	} catch(...){
		bitch("Caught an exception\n");
		return -1;
	}
	return 0;
}

void ec_print_policy(struct EntityContainer *ec,unsigned pid){
	try{
		ec->PrintPolicy(pid,std::cout);
	}catch(...){
		bitch("Caught an exception\n");
	}
}

const char *ec_get_block_page(struct EntityContainer *ec,unsigned pid){
	try{
		return ec->GetBlockPage(pid);
	}catch(...){
		bitch("Caught an exception\n");
		return 0;
	}
}

const char *ec_get_warn_page(struct EntityContainer *ec,unsigned pid){
	try{
		return ec->GetWarnPage(pid);
	}catch(...){
		bitch("Caught an exception\n");
		return 0;
	}
}

const char *ec_get_pac_file(struct EntityContainer *ec,unsigned eid){
	try{
		return ec->GetPacFile(eid);
	}catch(...){
		bitch("Caught an exception\n");
		return 0;
	}
}

const char *ec_get_password(struct EntityContainer *ec,unsigned eid){
	try{
		return ec->GetPassword(eid);
	}catch(...){
		bitch("Caught an exception\n");
		return 0;
	}
}

struct Predicate *pred_new(){
	try{
		return new Predicate();
	}catch(...){
		bitch("Caught an exception\n");
		return 0;
	}
}

void pred_delete(struct Predicate *p){
	delete p;
}

void pred_add_cat(struct Predicate *p,CategoryType cat){
	p->AddCat(cat);
}

void pred_set_rep(struct Predicate *p, int rep){
	p->SetRep(rep);
}

void pred_set_uid(struct Predicate *p, unsigned int uid){
	p->SetUid(uid);
}

void pred_set_hdrs(struct Predicate *p, const struct icap_state *is){
	p->SetHeaderData(is);
}

void pred_print(struct Predicate *p){
	std::cout << *p;
}

void pred_set_respmod_flag(struct Predicate *p) {
  p->SetRespmodFlag();
}
