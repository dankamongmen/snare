#ifndef POLICY_H
#define POLICY_H

#include <exception>
#include <iostream>
#include <string>
#include <cstring>
#include <set>
#include <list>
#include <map>
#include <vector>
#include <pcre.h>
#include <util/sfilter.h>
#include <policy/policy_types.h>
#include <libdank/objects/intervaltree.h>
#include "snare/icap/request.h"

#define MAX_SUPPORTED_POLICY_VERSION    1

struct lt_std_str {
  bool operator()(const std::string &s1, const std::string &s2) const {
    return strcmp(s1.c_str(), s2.c_str()) < 0;
  }
};

struct lt_case_std_str {
  bool operator()(const std::string &s1, const std::string &s2) const {
    return strcasecmp(s1.c_str(), s2.c_str()) < 0;
  }
};


class PolEx : public std::exception {
 public:
  PolEx() {
    str = "Policy exception";
  }
  PolEx(const char* astr) {
    str = astr;
  }
  virtual const char* what() const throw() {
    return str;
  }
  
 protected:
  const char *str;
};

class PolXmlEx : public PolEx {
 public:
  PolXmlEx() : PolEx("XML exception") {}
  PolXmlEx(const char* astr) : PolEx(astr) {}
};

class PolDupEx : public PolEx {
 public:
  PolDupEx() : PolEx("Duplicate ID") {}
  PolDupEx(const char* astr) : PolEx(astr) {}
};


class PolObject {
 public:
  PolObject();
  ~PolObject();
  static unsigned int GetCount();

 private:
  static unsigned int object_count;
};

class Rule;
class HTTPHeaderCheck;
class HeaderCheckList;
class UrlList;
class Predicate;
class Item;
class User;
class GenericUser;

class Container : public PolObject {
 public:
  Container();
  virtual ~Container();
  void Add(Item*);
  virtual void Del(unsigned int);
  Item* Get(unsigned int);

 protected:
  void DeleteAll();
  std::map<unsigned int, Item*> id_map;

  friend class Item;
};

class UserContainer : public Container {
 public:
  UserContainer();
  void Add(GenericUser*);
  virtual void Del(unsigned int);
  User* Get(const char*);
  GenericUser* Get(unsigned int);

 protected:
  std::map<std::string, User*, lt_std_str> name_map;
};

class Item : public PolObject {
 public:
  Item();
  Item(unsigned int);
  virtual ~Item();
  virtual void SetId(unsigned int);
  virtual unsigned int GetId();

 protected:
  unsigned int id;
  Container *container;
  
  friend class Container;
};

class GenericUser : public Item {	// Base class for users and netblocks
 public:
  GenericUser();
  void SetPolicyId(unsigned int);
  void SetEntityId(unsigned int);
  void SetGroupId(unsigned int);
  void SetQuotaFlag(bool flag = true) { over_quota = flag; }

 protected:
  unsigned int pid;
  unsigned int eid;
  unsigned int gid;
  bool over_quota;

  friend class EntityContainer;
};

class User : public GenericUser {
 public:
  User();
  ~User();
  void SetPasswordHash(const char*);
  void SetPasswordHA1(const char*);
  void SetPasswordNtlmHash(const char*);
  void SetUserName(const char*);
  const char* GetUserName();
  void AddAlias(const char*);
  const char* GetPasswordHA1();  // This is a null-terminated hex representation of the HA1 hash as required by RFC 2617
  const unsigned char* GetPasswordHash(); // This is a SHA-1 hash and not null-terminated
  const unsigned char* GetPasswordNtlmHash(); // This is an MD4 hash and not null-terminated

 protected:
  unsigned char *password_hash;
  std::string password_ha1;
  unsigned char *password_ntlmhash;
  std::string username;
  std::vector<std::string> aliases;
  friend class UserContainer;
  friend class Entity;
};

class Netblock : public GenericUser {
 public:
  Netblock();
  Netblock(uint32_t, uint32_t, unsigned int);
  void SetFromIP(uint32_t);
  void SetToIP(uint32_t);
  void UseNtlm();	// NTLM identification
  void UseNtlmAuth();	// NTLM authentication
  void UseCookieAuth();

 protected:
  uint32_t ip_from;
  uint32_t ip_to;
  bool use_ntlm, use_cookieauth, use_ntlm_auth;

  friend class EntityContainer;
};

class Policy : public Item {
 public:
  Policy();
  ~Policy();
  void AddRule(Rule*);
  void SetDefaultAction(ActionType);
  void SetBlacklist(unsigned int);
  void SetWhitelist(unsigned int);
  ActionType ApplyRules(Predicate&, const char**, unsigned int*);
  ActionType ApplyUrlLists(Container*,const char *);
  const char* GetBlockPage();
  const char* GetWarnPage();
  void SetBlockPage(const char*);
  void SetWarnPage(const char*);
  void SetTzOffset(int);
  void SetForceSafeSearch(bool ss = true);
  void SetBypassAntiMalware(bool byp = true);

  friend std::ostream& operator<<(std::ostream&, const Policy&);

 protected:
  std::list<Rule*> rules;
  unsigned int blacklist_id;
  unsigned int whitelist_id;
  ActionType default_action;
  std::string block_page;
  std::string warn_page;
  int tz_offset;
  bool force_safe_search;
  bool bypass_anti_malware;
  
  friend class EntityContainer;
};

class Rule : public Item {
 public:
  Rule();
  ~Rule();
  void SetMinRep(int);
  void SetMaxRep(int);
  void ClearCats();
  void ClearUids();
  void AddCat(CategoryType);
  void SetTimeRange(unsigned int, unsigned int);
  void SetQuotaFlag(bool flag = true) { check_quota = flag; } 
  void SetWeekdays(bool, bool, bool, bool, bool, bool, bool);
  void SetAction(ActionType);
  void SetAlertEmailAddr(const char*);
  void SetRuleName(const char*);
  void AddOnlyForUid(unsigned int);
  void AddAllButUid(unsigned int);
  void AddHeaderCheckList(HeaderCheckList*);
  const char* GetAlertEmailAddr();
  const char* GetRuleName();
  bool IsMatch(Predicate&);
  bool IsMatch(Predicate&, bool&);
  ActionType GetAction();

  friend std::ostream& operator<<(std::ostream&, const Rule&);

 protected:
  int rep_min, rep_max;
  unsigned int time_min, time_max;
  bool mon, tue, wed, thu, fri, sat, sun;
  bool check_quota;
  std::set<CategoryType> cat_set;
  std::set<unsigned int> uid_onlyfor_set, uid_allbut_set;
  ActionType action;
  std::string alert_email_addr, rule_name;
  // These really should go into two lists since we're never doing request and
  // response headers in the same run.
  std::list<HeaderCheckList*> hdr_lists;
  bool require_respmod;

  friend class Policy;
};

// Lists of header rules can contain header rules or (recursively) more lists
// of header rules. This object abstracts the two into on class.
class HdrCheckObject : public PolObject {
 public:
  HdrCheckObject();
  virtual ~HdrCheckObject();
  virtual bool IsMatch(Predicate&) = 0;
  
 protected:
  bool require_respmod;

  friend class HeaderCheckList;
};

// A check for a single HTTP header
class HTTPHeaderCheck: public HdrCheckObject {
 public:
   HTTPHeaderCheck();
   ~HTTPHeaderCheck();
   void SetHeader(HeaderCheckType, const char*, const char*, HeaderCheckOp);
   bool IsMatch(Predicate&);
   const char* GetName() { return name.c_str(); }
   HeaderCheckType GetType() { return type; }

   friend std::ostream& operator<<(std::ostream&, const HTTPHeaderCheck&);
 protected:
   std::string name, condition;
   double d_condition;
   HeaderCheckType type;
   HeaderCheckOp op;
   pcre *regex;
   pcre_extra *regex_extra;
   pcre_extra regex_extra_static;
};

// A list of HdrCheckObjects (i.e. either single headers to check or other
// lists like this)
class HeaderCheckList : public HdrCheckObject {
 public:
  HeaderCheckList();
  ~HeaderCheckList();
  void AddHeaderCheckObject(HdrCheckObject*);
  void AddHTTPHeaderCheck(HTTPHeaderCheck*); // obsoloted by above; keep for unit tests
  bool IsMatch(Predicate&);		// evaluate this list (and headers and the lists in this list)
  void UseOr() { use_or = true; }	// use OR condition for everything in this list
  void UseAnd() { use_or = false; }	// use AND condition (default)

 protected:
  std::list<HdrCheckObject*> hdr_checks;
  bool use_or;

  friend class Rule;
};

class UrlList : public Item {
 public:
  UrlList();
  ~UrlList();
  void AddUrl(const char*);
  bool UrlMatch(const char *);
  static void DeleteUrlList(unsigned int);

  friend std::ostream& operator<<(std::ostream&, const UrlList&);

 protected:
  std::list<std::string> urls;
  struct sfilter_policy *spol;
  unsigned int id;

  friend class Policy;
  friend class EntityContainer;
};

class Entity : public Item {
 public:
  Entity();
  Entity(unsigned int);

  void AddNetblock(Netblock*);
  void AddUser(User*);
  void AddAuthUrl(const char*);
  void SetId(unsigned int);
  void SetPacFile(const char*);
  void SetPassword(const char*);
  void UseWfaSaml();
  const char* GetPassword();
  bool IsAuthPage(const char*);

 protected:
  unsigned int id;
  bool use_wfa_saml;
  std::vector<Netblock*> netblocks;
  std::vector<User*> users;
  std::map<std::string, unsigned int, lt_case_std_str> alias_map;
  std::string PAC_file;
  std::string pw;
  UrlList auth_page_list;
  friend class EntityContainer;
};

class EntityContainer : public PolObject {
 public:
  EntityContainer();
  ~EntityContainer();
  void AddEntity(Entity*);
  void DelEntity(unsigned int);
  bool GetWfaSamlFlag(unsigned int);
  void GetPolDataForIP(uint32_t, unsigned int*, unsigned int*, unsigned int*, unsigned int*, bool*, bool*, bool*);
  void GetPolDataForUid(unsigned int, unsigned int*, unsigned int*, unsigned int*);
  char* GetUserForUid(unsigned int);
  char* GetNetblockForIP(uint32_t);
  unsigned int GetUidForAlias(unsigned int eid, const char*);
  void optimizeEC();

  ActionType ApplyPolicyRules(unsigned int, Predicate&, const char**, unsigned int*, bool&, bool&);
  ActionType ApplyPolicyUrlLists(unsigned int, const char*);
  void PrintPolicy(unsigned int, std::ostream& os = std::cout);
  const char* GetBlockPage(unsigned int);
  const char* GetWarnPage(unsigned int);
  const char* GetPacFile(unsigned int);
  const char* GetPassword(unsigned int);
  Container& GetPolicyContainer();
  Container& GetUrlListContainer();
  Container& GetRuleContainer();
  UserContainer& GetUserContainer();
  unsigned int GetNetblockCount();
  bool IsAuthPage(unsigned int, const char*);

 protected:
  std::map<unsigned int, Entity*> ent_id_map;	// maps entity ids to entity objects
  UserContainer user_cont;
  Container pol_cont;
  Container urllist_cont;
  Container rule_cont;
  struct interval_tree *nb_itree;
};

class Predicate {
 public:
  Predicate();
  void AddCat(CategoryType);
  void SetRep(int);
  void CalcTime(int);
  void SetUid(unsigned int);
  void SetQuotaFlag(bool flag = true) { over_quota = flag; }
  void SetRespmodFlag(bool flag = true) { is_respmod = flag; }
  void SetHeaderData(const struct icap_state*);
  void SetHeaderDebug(const char*, const char*);
  //void SetUrl(const char*);
  char *SerializeCore();
  void DeserializeCore(const char*);
  bool CoreCmp(Predicate&);

  friend std::ostream& operator<<(std::ostream&, const Predicate&);

 protected:
  bool have_time, over_quota, is_respmod;
  //std::string url;
  unsigned int secs_since_midnight;
  unsigned int weekday;
  int rep;
  std::set<CategoryType> cat_set;
  unsigned int uid;
  std::map<std::string, const char*, lt_std_str> http_req_hdrs;
  std::map<std::string, const char*, lt_std_str> http_resp_hdrs;
  const char *http_startline, *http_method, *http_url, *http_ver;
  const char *http_statusline, *http_resver, *http_statuscode, *http_exposition;

  friend class Rule;
  friend class HTTPHeaderCheck;
  friend class Policy;
  friend class EntityContainer;
};

#endif
