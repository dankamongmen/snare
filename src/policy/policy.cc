#include <time.h>
#include <sstream>
#include <iterator>
#include <algorithm>
#include <typeinfo>
#include <libdank/utils/string.h>
#include <libdank/utils/rfc2396.h>
#include <libdank/objects/logctx.h>
#include <libdank/objects/lexers.h>
#include <libdank/utils/memlimit.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "policy.h"
#include "util/url_escape.h"
#include "util/misc.h"

#define DEFAULT_BLOCK_PAGE \
	"<html><body><h1>Blocked</h1><p>The requested page is blocked by your company's policy</p></body></html>"
#define DEFAULT_WARN_PAGE \
	"<html><body><h1>Warning</h1>" \
	"<p>The site you are navigating you is potentially harmful. " \
	"If you wish to proceed nonetheless, please follow this link:</p>" \
	"%%LINK%%" \
	"</body></html>"

#define DEFAULT_PAC_FILE \
    "function FindProxyForURL(url, host)" \
    "{" \
        "if(url.substring(0,7) == \"http://\")" \
        "{" \
            "if(dnsDomainIs(host, \"localhost\"))" \
            "{" \
                "return \"DIRECT\";" \
            "}" \
            "return \"PROXY swps-proxy.securecomputing.com:8080\";" \
        "}" \
        "return \"DIRECT\";" \
    "}"

template <class T>
bool from_string(T& t,
                 const std::string& s,
                 std::ios_base& (*f)(std::ios_base&))
{
    std::istringstream iss(s);
    return !(iss >> f >> t).fail();
}

std::ostream& operator<<(std::ostream &os, const Rule &r) {
  std::set<CategoryType>::const_iterator cur;
  std::set<unsigned int>::const_iterator cur_uid;
  // std::list<HTTPHeaderCheck*>::const_iterator cur_hdr;
  
  os << r.rep_min << " <= rep <= " << r.rep_max
     << "; categories:";
  for(cur = r.cat_set.begin(); cur != r.cat_set.end(); cur++) {
    os << " " << *cur;
  }
  os << "; " << r.time_min << " <= time <= " << r.time_max
     << "; weekdays:";
  if(r.mon) os << " Mon";
  if(r.tue) os << " Tue";
  if(r.wed) os << " Wed";
  if(r.thu) os << " Thu";
  if(r.fri) os << " Fri";
  if(r.sat) os << " Sat";
  if(r.sun) os << " Sun";
  os <<  "; uids:";
  for(cur_uid = r.uid_onlyfor_set.begin(); cur_uid != r.uid_onlyfor_set.end(); cur_uid++) {
    os << " " << *cur_uid;
  }
  /* xxx fixme: add this back
  os <<  "; header checks:";
  for(cur_hdr = r.hdr_checks.begin(); cur_hdr != r.hdr_checks.end(); cur_hdr++) {
    os << " " <<  **cur_hdr;
    }*/
  os << "; action: " << r.action;

  return os;
}

std::ostream& operator<<(std::ostream &os, const HTTPHeaderCheck &hc) {

  switch(hc.type) {
    case TYPE_REQMOD:
      os << "REQMOD ";
      break;
    case TYPE_RESPMOD:
      os << "RESPMOD ";
      break;
    case TYPE_STARTLINE:
      os << "STARTLINE ";
      break;
    case TYPE_STATUSLINE:
      os << "STATUSLINE ";
      break;
  }
  os << hc.name;
  switch(hc.op) {
    case OP_REGEX:
      os << "=~";
      break;
    case OP_GT:
      os << ">";
      break;
    case OP_GTEQ:
      os << ">=";
      break;
    case OP_EQ:
      os << "==";
      break;
    case OP_LT:
      os << "<";
      break;
    case OP_LTEQ:
      os << "<=";
      break;
  }
  os << hc.condition;

  return os;
}

std::ostream& operator<<(std::ostream &os, const Policy &p) {
  std::list<Rule*>::const_iterator cur;
  unsigned int i = 1;

  os << "policy " << p.id << ":\n";
  for(cur = p.rules.begin(); cur != p.rules.end(); cur++) {
    os << (i++) << ": " << **cur << "\n";
  }
  os << "default action: " << p.default_action << "\n";

  return os;
}

std::ostream& operator<<(std::ostream &os, const UrlList &u) {
  std::list<std::string>::const_iterator cur;
  unsigned int i = 1;

  os << "URL list " << u.id << ":\n";
  for(cur = u.urls.begin(); cur != u.urls.end(); cur++) {
    os << (i++) << ": " << *cur << "\n";
  }

  return os;
}

std::ostream& operator<<(std::ostream &os, const Predicate &p) {
  std::set<CategoryType>::const_iterator cur;
  std::map<std::string, const char*, lt_std_str>::const_iterator curhdr;
 
  os << "uid " << p.uid << "; ";
  os << "rep " << p.rep
     << "; categories:";
  for(cur = p.cat_set.begin(); cur != p.cat_set.end(); cur++) {
    os << " " << *cur;
  }
  if(p.have_time) {
    os << "; " << p.secs_since_midnight << " secs; weekday = " << p.weekday;
  }
  os << "; startline: " << p.http_startline;
  os << "; method: " << p.http_method;
  os << "; url: " << p.http_url;
  os << "; ver: " << p.http_ver;
  os << "; request headers:";
  for(curhdr = p.http_req_hdrs.begin(); curhdr != p.http_req_hdrs.end(); curhdr++) {
    if(curhdr->second) {
      os << " " << curhdr->first << "=" << curhdr->second;
    }
  }
  if(p.is_respmod) {
    os << "; statusline: " << p.http_statusline;
    os << "; resver: " << p.http_resver;
    os << "; statuscode: " << p.http_statuscode;
    os << "; exposition: " << p.http_exposition;
    os << "; response headers:";
    for(curhdr = p.http_resp_hdrs.begin(); curhdr != p.http_resp_hdrs.end(); curhdr++) {
      if(curhdr->second) {
	os << " " << curhdr->first << "=" << curhdr->second;
      }
    }
  } else {
    os << "; no respmod data";
  }

  os << std::endl;
  return os;
}


unsigned int PolObject::object_count = 0;

PolObject::PolObject() {
  object_count++;
}

PolObject::~PolObject() {
  object_count--;
}

unsigned int PolObject::GetCount() {
  return object_count;
}


Container::Container() : PolObject() {
}

Container::~Container() {
  DeleteAll();
}

void Container::Add(Item *item) {
  unsigned int id = item->GetId();
  if(id_map.count(id)) {
    bitch("Duplicate id (%u), throwing exception\n", id);
    throw PolDupEx();
  }
  id_map[id] = item;
  item->container = this;
}

Item* Container::Get(unsigned int aid) {
  if(id_map.count(aid)) {
    return id_map[aid];
  }
  return 0;
}

void Container::Del(unsigned int aid) {
  if(id_map.count(aid)) {
    // The Item destructor will remove the key from id_map
    delete id_map[aid];
  }
}

void Container::DeleteAll() {
  std::map<unsigned int, Item*>::iterator cur;
  for(cur = id_map.begin(); cur != id_map.end();) {
    Del(cur++->first);
  }
}


UserContainer::UserContainer() : Container() {
}

void UserContainer::Add(GenericUser *gu) {
  Container::Add(gu);

  User *u = dynamic_cast<User*>(gu);
  if(u) {
    name_map[u->username] = u;
  }

}

void UserContainer::Del(unsigned int aid) {
  if(id_map.count(aid)) { // xxx why is this always false?
    User *u = dynamic_cast<User*>(id_map[aid]);
    if(u) {
      name_map.erase(u->username);
    }
    delete id_map[aid];
    id_map.erase(aid);
  }
}

User* UserContainer::Get(const char *uname) {
  if(name_map.count(uname)) {
    return name_map[uname];
  }
  return 0;
}

GenericUser* UserContainer::Get(unsigned int aid) {
  return static_cast<GenericUser*>(Container::Get(aid));
}

Item::Item() : PolObject(), id(0), container(0) {
}

Item::Item(unsigned int aid) : id(aid) {
}

Item::~Item() {
  if(container && id && container->id_map.count(id)) { 
    container->id_map.erase(id);
  }
}

void Item::SetId(unsigned int aid) {
  id = aid;
}

unsigned int Item::GetId() {
  return id;
}


GenericUser::GenericUser() : Item(), pid(0), over_quota(false) {
}

void GenericUser::SetPolicyId(unsigned int policy_id) {
  pid = policy_id;
}

void GenericUser::SetEntityId(unsigned int entity_id) {
  eid = entity_id;
}

void GenericUser::SetGroupId(unsigned int group_id) {
  gid = group_id;
}


User::User() : GenericUser(), password_hash(0), password_ha1(""), password_ntlmhash(0) {
}

User::~User() {
  Free(password_hash);
  Free(password_ntlmhash);
}

void User::SetUserName(const char *name) {
  username = name;
}

const char* User::GetUserName() {
  return username.c_str();
}

void User::SetPasswordHA1(const char *pw) {
  password_ha1 = pw;
}

void User::AddAlias(const char *alias) {
  aliases.push_back(alias);
}

const char* User::GetPasswordHA1() {
  return password_ha1.c_str();
}

void User::SetPasswordHash(const char *pwhash) {
  password_hash = convert_ascii_sha1(pwhash);
  if(!password_hash) {
    throw PolEx("Error converting/allocating password hash");
  }
}

void User::SetPasswordNtlmHash(const char *pwhash) {
  password_ntlmhash = convert_ascii_md4(pwhash);
  if(!password_ntlmhash) {
    throw PolEx("Error converting/allocating password ntlm hash");
  }
}

const unsigned char* User::GetPasswordHash() {
  return password_hash;
}

const unsigned char* User::GetPasswordNtlmHash() {
  return password_ntlmhash;
}


Netblock::Netblock() : GenericUser(), ip_from(0), ip_to(0), use_ntlm(false),
		       use_cookieauth(false), use_ntlm_auth(false) {
}

Netblock::Netblock(uint32_t from, uint32_t to, unsigned int polid)
  : GenericUser(), ip_from(from), ip_to(to), use_ntlm(false), use_cookieauth(false),
    use_ntlm_auth(false)
{
  SetPolicyId(polid);
}

void Netblock::SetFromIP(uint32_t ip) {
  ip_from = ip;
}

void Netblock::SetToIP(uint32_t ip) {
  ip_to = ip;
}

void Netblock::UseNtlm() {
  use_ntlm = true;
}

void Netblock::UseNtlmAuth() {
  use_ntlm_auth = true;
}

void Netblock::UseCookieAuth() {
  use_cookieauth = true;
}


Policy::Policy() : Item(), blacklist_id(0), whitelist_id(0), default_action(ACT_NULL),
		   block_page(DEFAULT_BLOCK_PAGE), warn_page(DEFAULT_WARN_PAGE),
		   tz_offset(0), force_safe_search(false), bypass_anti_malware(false)
{
}

Policy::~Policy() {
  // Rules get now deleted when the EntityContainer is destructed. Since policy destruction
  // is currently triggered by EntityContainer::pol_cont destruction, rules may be already gone
  // since rule_cont is destructed in the same way. Need to clean this up so that deleting a
  // policy also deletes all the associated rules (This will be needed once we do diffs).

  //std::list<Rule*>::iterator cur;
  //for(cur = rules.begin(); cur != rules.end(); cur++) {
  //    delete *cur;
  //}
}

void Policy::AddRule(Rule *rule) {
  rules.push_back(rule);
}

void Policy::SetDefaultAction(ActionType act) {
  default_action = act;
}

void Policy::SetBlacklist(unsigned int lid) {
  blacklist_id = lid;
}

void Policy::SetWhitelist(unsigned int lid) {
  whitelist_id = lid;
}


ActionType Policy::ApplyRules(Predicate &pred, const char **alert_email_addr, unsigned int *rule_id) {
  std::list<Rule*>::iterator cur;
  Rule *rule;
  bool is_match, need_respmod;

  for(cur = rules.begin(); cur != rules.end(); cur++) {
    rule = *cur;
    is_match = rule->IsMatch(pred, need_respmod);
    if(need_respmod) {
      nag("Rule %u requires RESPMOD data\n", rule->GetId());
      return ACT_NEED_RESPMOD;
    }
    if(is_match) {
      *alert_email_addr = rule->GetAlertEmailAddr();
      *rule_id = rule->GetId();
      return rule->GetAction();
    }
  }
  *alert_email_addr = 0;
  *rule_id = 0;
  return default_action;
}

ActionType Policy::ApplyUrlLists(Container *urllists,const char *uri){
  UrlList *ul;

  if(blacklist_id && (ul = static_cast<UrlList*>(urllists->Get(blacklist_id)))) {
    if(ul->UrlMatch(uri)){
      nag("Matched blacklist <%s>\n",uri);
      return ACT_BLOCK;
    }
  }

  if(whitelist_id && (ul = static_cast<UrlList*>(urllists->Get(whitelist_id)))) {
    if(ul->UrlMatch(uri)){;
      nag("Matched whitelist <%s>\n",uri);
      return ACT_ALLOW;
    }
  }
  return ACT_NULL;
}

const char* Policy::GetBlockPage() {
  return block_page.c_str();
}

const char* Policy::GetWarnPage() {
  return warn_page.c_str();
}

void Policy::SetBlockPage(const char *html) {
  block_page = html;
}

void Policy::SetWarnPage(const char *html) {
  warn_page = html;
}

void Policy::SetTzOffset(int off) {
  tz_offset = off;
}

void Policy::SetForceSafeSearch(bool ss) {
  force_safe_search = ss;
}

void Policy::SetBypassAntiMalware(bool byp) {
  bypass_anti_malware = byp;
}


Rule::Rule() : Item(),
	       rep_min(-1000),
	       rep_max(1000),
	       time_min(0),
	       time_max(86400),
	       mon(true),
	       tue(true),
	       wed(true),
	       thu(true),
	       fri(true),
	       sat(true),
	       sun(true),
	       check_quota(false),
	       action(ACT_NULL),
	       alert_email_addr(""),
	       rule_name(""),
	       require_respmod(false)
{
}

Rule::~Rule() {
    std::list<HeaderCheckList*>::iterator cur;
    for(cur = hdr_lists.begin(); cur != hdr_lists.end(); cur++) {
        delete *cur;
    }
}

void Rule::SetMinRep(int rep) {
  rep_min = rep;
}

void Rule::SetMaxRep(int rep) {
  rep_max = rep;
}

void Rule::ClearCats() {
  cat_set.clear();
}

void Rule::ClearUids() {
  uid_onlyfor_set.clear();
  uid_allbut_set.clear();
}

void Rule::AddCat(CategoryType cat) {
  cat_set.insert(cat);
}

void Rule::AddOnlyForUid(unsigned int uid) {
  uid_onlyfor_set.insert(uid);
}

void Rule::AddAllButUid(unsigned int uid) {
  uid_allbut_set.insert(uid);
}

void Rule::SetTimeRange(unsigned int start, unsigned int end) {
  time_min = start;
  time_max = end;
}

void Rule::SetWeekdays(bool monday,
		       bool tuesday,
		       bool wednesday,
		       bool thursday,
		       bool friday,
		       bool saturday,
		       bool sunday)
{
  mon = monday;
  tue = tuesday;
  wed = wednesday;
  thu = thursday;
  fri = friday;
  sat = saturday;
  sun = sunday;
}

void Rule::SetAction(ActionType act) {
  action = act;
}

void Rule::SetAlertEmailAddr(const char *addr) {
  alert_email_addr = addr;
}

const char* Rule::GetAlertEmailAddr() {
  return alert_email_addr.c_str();
}

void Rule::SetRuleName(const char *name) {
  rule_name = name;
}

void Rule::AddHeaderCheckList(HeaderCheckList* lst) {
  if(lst->require_respmod) {
    require_respmod = true;
  }
  hdr_lists.push_back(lst);
}

const char* Rule::GetRuleName() {
  return rule_name.c_str();
}

bool Rule::IsMatch(Predicate &pred) {
  bool dummy;
  return IsMatch(pred, dummy);
}

bool Rule::IsMatch(Predicate &pred, bool &_require_respmod) {
  // Check if uid is in exclusion set

  nag("Rule id %u\n", id);

  if(require_respmod && !pred.is_respmod) {
    _require_respmod = true;
    return false;
  } else {
    _require_respmod = false;
  }


  if(uid_allbut_set.count(pred.uid)) {
    nag("uid excluded\n");
    return false;
  }

  if(check_quota) {
    if(!pred.over_quota) {
      return false;
    }
  }

  if(pred.have_time) {
    switch(pred.weekday) {
    case 0:
      if(!sun)
	return false;
      break;
    case 1:
      if(!mon)
	return false;
      break;
    case 2:
      if(!tue)
	return false;
      break;
    case 3:
      if(!wed)
	return false;
      break;
    case 4:
      if(!thu)
	return false;
      break;
    case 5:
      if(!fri)
	return false;
      break;
    case 6:
      if(!sat)
	return false;
      break;
    }
  
    if(!(pred.secs_since_midnight >= time_min && pred.secs_since_midnight <= time_max)) {
      return false;
    }
  }

  if(!(pred.rep >= rep_min && pred.rep <= rep_max)) {
    return false;
  }

  // Only test for categories if rule includes categories
  if(!cat_set.empty()) {
    // Check whether at least one category in the rule is also present in the predicate
    std::set<CategoryType> intersection;
    std::insert_iterator<std::set<CategoryType> > ii(intersection, intersection.begin());
    std::set_intersection(pred.cat_set.begin(), pred.cat_set.end(), cat_set.begin(), cat_set.end(), ii);
    if(intersection.empty()) {
      // nag("Empty intersection\n");
      return false;
    }
    std::stringstream ss;
    std::copy(intersection.begin(), intersection.end(), std::ostream_iterator<CategoryType>(ss, " "));
    nag("Category intersection: %s\n", ss.str().c_str());
  } else {
    nag("No categories in rule\n");
  }

  // Only test for uids if rule includes uids
  if(!uid_onlyfor_set.empty()) {
    if(uid_onlyfor_set.count(pred.uid)) {
      nag("uid matched in rule condition\n");
    } else {
      return false;
    }
  }

  // Everything else matches, now one of the header check lists needs to match
  // ... but only if there are any
  if(hdr_lists.begin() == hdr_lists.end()) {
    return true;
  }
  std::list<HeaderCheckList*>::iterator hdrlst_cur;
  for(hdrlst_cur = hdr_lists.begin(); hdrlst_cur != hdr_lists.end(); hdrlst_cur++) {
    if((*hdrlst_cur)->IsMatch(pred)) {
      return true;
    }
  }
  // None of the header check lists matched
  return false;

}

ActionType Rule::GetAction() {
  return action;
}


HTTPHeaderCheck::HTTPHeaderCheck() : HdrCheckObject(),
                                   name(""),
                                   condition(""),
                                   d_condition(0),
                                   type(TYPE_REQMOD),
                                   op(OP_REGEX),
                                   regex(NULL),
                                   regex_extra(NULL)
{
}

HTTPHeaderCheck::~HTTPHeaderCheck() {
  if(regex != NULL)
  {
    pcre_free(regex);
  }
  if(regex_extra != NULL && regex_extra != &regex_extra_static)
  {
    pcre_free(regex_extra);
  }
}

void HTTPHeaderCheck::SetHeader(HeaderCheckType atype, const char *h_name, const char *h_cond, HeaderCheckOp op_id) {
    type = atype;
    op = op_id;
    if(type == TYPE_RESPMOD || type == TYPE_STATUSLINE) {
      require_respmod = true;
    }
    if(op == OP_REGEX) {
      const char *err_msg;
      int err_offset;

      /* Compile pattern */
      regex = pcre_compile(h_cond, /* the pattern */
			   PCRE_NO_AUTO_CAPTURE | PCRE_UTF8, /* options */
			   &err_msg, /* for error message */
			   &err_offset, /* for error offset */
			   NULL); /* use default character table */
      if(regex == NULL)
      {
        bitch("Failed to compile regex '%s' due to error: '%s' at offset %d\n", h_cond, err_msg, err_offset);
        throw PolEx("HTTPHeaderCheck::SetHeader: failed to compile regular expression");
      }
      /* Optimize pattern */
      regex_extra = pcre_study(regex, 0, &err_msg);
      if(err_msg != NULL)
      {
        bitch("Failed to optimize regex '%s' due to error: '%s'\n", h_cond, err_msg);
        throw PolEx("HTTPHeaderCheck::SetHeader: failed to optimize regular expression");
      }
      if(regex_extra == NULL)
      {
        regex_extra = &regex_extra_static;
        regex_extra->flags = 0;
      }
      regex_extra->match_limit = 30;
      regex_extra->match_limit_recursion = 30;
      regex_extra->flags |= PCRE_EXTRA_MATCH_LIMIT | PCRE_EXTRA_MATCH_LIMIT_RECURSION;
    }
    else {
      switch(op) {
        case OP_GT:
        case OP_GTEQ:
        case OP_EQ:
        case OP_LT:
        case OP_LTEQ:
          /* Numeric Operation */
          if(!from_string<double>(d_condition, std::string(h_cond), std::dec)) {
            throw PolEx("HTTPHeaderCheck::SetHeader: invalid numeric condition");
          }
          break;
        default:
          throw PolEx("HTTPHeaderCheck::SetHeader: unrecognized operation");
      }
    }
    name = h_name;
    condition = h_cond;
}

bool HTTPHeaderCheck::IsMatch(Predicate &pred) {
  const char *hdrval = "", *hdrname = name.c_str();
  if(type == TYPE_REQMOD) {
    if(pred.http_req_hdrs.count(hdrname)) {
      hdrval = pred.http_req_hdrs[hdrname];
    }
  } else if(type == TYPE_RESPMOD) {
    if(pred.http_resp_hdrs.count(hdrname)) {
      hdrval = pred.http_resp_hdrs[hdrname];
    }
  } else if(type == TYPE_STARTLINE) {
    if(strcasecmp(hdrname, "method") == 0) {
      hdrval = pred.http_method;
    } else if(strcasecmp(hdrname, "url") == 0) {
      hdrval = pred.http_url;
    } else if(strcasecmp(hdrname, "httpver") == 0) {
      hdrval = pred.http_ver;
    } else if(strcasecmp(hdrname, "startline") == 0) {
      hdrval = pred.http_startline;
    }
  } else if(type == TYPE_STATUSLINE) {
    if(strcasecmp(hdrname, "httpresver") == 0) {
      hdrval = pred.http_resver;
    } else if(strcasecmp(hdrname, "statuscode") == 0) {
      hdrval = pred.http_statuscode;
    } else if(strcasecmp(hdrname, "exposition") == 0) {
      hdrval = pred.http_exposition;
    } else if(strcasecmp(hdrname, "statusline") == 0) {
      hdrval = pred.http_statusline;
    }
  }
  if(op == OP_REGEX) {
    int rc;
    int ovector[30];
    rc = pcre_exec(regex, /* the compiled pattern */
                   regex_extra , /* extra data obtained by studying pattern */
                   hdrval, /* the subject string */
                   strlen(hdrval), /* the length of the subject */
                   0, /* start at offset 0 in the subject */
                   0, /* default options */
                   ovector, /* output vector for substring information */
                   30); /* number of elements in the output vector */
    if(rc >= 0)
    {
      return true;
    }
    else
    {
      nag("Failed to match header regex '%s' to '%s': %d\n", condition.c_str(), hdrval, rc);
      return false;
    }
  }
  else {
    /* Numeric Operation */
    double vd;
    double diff;
    if(!from_string<double>(vd, std::string(hdrval), std::dec)) {
        nag("Unable to parse header value as numeric: %s\n", hdrval);
        return false;
    }

    switch(op) {
      case OP_GT:
        if(vd > d_condition) return true;
        break;
      case OP_GTEQ:
        if(vd >= d_condition) return true;
        break;
      case OP_EQ:
        if(vd > d_condition)
            diff = vd - d_condition;
        else
            diff = d_condition - vd;
        if(diff < 0.00000001) return true;
        break;
      case OP_LT:
        if(vd < d_condition) return true;
        break;
      case OP_LTEQ:
        if(vd <= d_condition) return true;
        break;
      default:
        nag("Invalid HTTPHeaderCheck operator: %d\n", op);
        return false;
    }
    nag("Failed to match header condition: %f %d %f\n", vd, op, d_condition);
  }

  return false;
}


HdrCheckObject::HdrCheckObject() :  require_respmod(false) {
}

HdrCheckObject::~HdrCheckObject() {
}


HeaderCheckList::HeaderCheckList() : HdrCheckObject(),
				     use_or(false) {
}

HeaderCheckList::~HeaderCheckList() {
  std::list<HdrCheckObject*>::iterator cur;
  for(cur = hdr_checks.begin(); cur != hdr_checks.end(); cur++) {
    delete *cur;
  }
}

void HeaderCheckList::AddHeaderCheckObject(HdrCheckObject* hdr) {
  if(hdr->require_respmod) {
    // Now that we have complex AND/OR rules, we should refine the
    // mechanism that determines if we delay to respmod since some
    // header checks may never be evaluated.
    require_respmod = true;
  }
  hdr_checks.push_back(hdr);
}

void HeaderCheckList::AddHTTPHeaderCheck(HTTPHeaderCheck* hdr) {
  AddHeaderCheckObject(hdr);
}



bool HeaderCheckList::IsMatch(Predicate &pred) {
  std::list<HdrCheckObject*>::iterator hdr_cur;
  if(use_or) {
    // logical or -- bail when first rule matches
    for(hdr_cur = hdr_checks.begin(); hdr_cur != hdr_checks.end(); hdr_cur++) {
      if((*hdr_cur)->IsMatch(pred)) {
	return true;
      }
    }
    return false; // no rule matched, list doesn't match
  } else {
    // logical and -- bail when first rule doesn't match
    for(hdr_cur = hdr_checks.begin(); hdr_cur != hdr_checks.end(); hdr_cur++) {
      if(!(*hdr_cur)->IsMatch(pred)) {
	return false;
      }
    }
    return true; // all rules matched, list matches
  }
}


UrlList::UrlList() : Item() {
	if((spol = sfilter_policy_create()) == 0){
		throw PolEx("sfilter_policy_create");
	}
}

UrlList::~UrlList() {
	sfilter_policy_destroy(spol);
}

void UrlList::AddUrl(const char *url) {
  char *unesc_url = strdup(url);
  size_t s = 0;
  unsigned int i;

  if(!unesc_url) {
    throw std::bad_alloc();
  }
  SFUT_RFC1738Unescape(unesc_url, &s);
  for(i = 0; i < strlen(unesc_url); i++) {
    unesc_url[i] = tolower(unesc_url[i]);
  }
  urls.push_back(unesc_url);
  free(unesc_url);

  // xxx Is the above code still needed? I'd assume it has been completely
  //     absorbed by the SF-based solution.

  if(sfilter_policy_adduri(spol,url,SFILTER_HANDLERLIST)){
	  // FIXME: Remove URI from urls!
	  throw PolEx("sfilter_policy_adduri");
  }
}

bool UrlList::UrlMatch(const char *uri){
	int query;
	
	if((query = sfilter_uri_query(spol,uri)) < 0){
		throw PolEx("sfilter_uri_query");
	}
	return query;
}


Entity::Entity() : Item(), use_wfa_saml(false), PAC_file(DEFAULT_PAC_FILE) {
}

Entity::Entity(unsigned int eid) : Item(eid), use_wfa_saml(false), PAC_file(DEFAULT_PAC_FILE) {
}

void Entity::UseWfaSaml() {
  use_wfa_saml = true;
}

void Entity::AddNetblock(Netblock *nb) {
  nb->SetEntityId(id);
  netblocks.push_back(nb);
}

void Entity::AddUser(User *u) {
  u->SetEntityId(id);
  users.push_back(u);

  std::vector<std::string>::iterator cur;
  for(cur = u->aliases.begin(); cur != u->aliases.end(); cur++) {
    alias_map[*cur] = u->id;
  }
}

void Entity::SetPassword(const char *passwd) {
  pw = passwd;
}

// Since this gets always hex2bin converted by the code that uses this, we
// should do this already here.
const char* Entity::GetPassword() {
  return pw.c_str();
}

void Entity::SetId(unsigned int ent_id) {
  id = ent_id;
}

void Entity::SetPacFile(const char *file) {
  PAC_file = file;
}

void Entity::AddAuthUrl(const char *url) {
  auth_page_list.AddUrl(url);
}

bool Entity::IsAuthPage(const char *url) {
  if(auth_page_list.UrlMatch(url)) {
    nag("Matched authlist <%s>\n", url);
    return true;
  }
  return false;
}

EntityContainer::EntityContainer() : PolObject(), nb_itree(0) {
}

void EntityContainer::optimizeEC(){
	balance_interval_tree(&nb_itree);
}

EntityContainer::~EntityContainer() {
  std::map<unsigned int, Entity*>::iterator cur;
  for(cur = ent_id_map.begin(); cur != ent_id_map.end();) {
    DelEntity(cur++->first);
  }
  free_interval_tree(&nb_itree, 0);
}

bool EntityContainer::IsAuthPage(unsigned int eid, const char *url) {
  if(ent_id_map.count(eid) == 0) {
    return false;
  }

  Entity *ent = ent_id_map[eid];

  return ent->IsAuthPage(url);
}

void EntityContainer::GetPolDataForIP(uint32_t ip, unsigned int *uid, unsigned int *pid,
				      unsigned int *eid, unsigned int *gid, bool *use_ntlm_ident,
				      bool *use_ntlm_auth, bool *use_cookieauth) {
  Netblock *nb;
  nb = static_cast<Netblock*>(lookup_interval_tree(nb_itree, ip));
  if(nb) {
    *uid = nb->id;
    *pid = nb->pid;
    *eid = nb->eid;
    *gid = nb->gid;
    *use_ntlm_ident = nb->use_ntlm;
    *use_ntlm_auth = nb->use_ntlm_auth;
    *use_cookieauth = nb->use_cookieauth;
  } else {
    *pid = *eid = *uid = *gid = 0;
    *use_ntlm_ident = *use_ntlm_auth = *use_cookieauth = false;
  }
}

void EntityContainer::GetPolDataForUid(unsigned int uid, unsigned int *pid, unsigned int *eid, unsigned int *gid) {
  User *u;
  u = static_cast<User*>(user_cont.Get(uid));
  if(u) {
    *pid = u->pid;
    *eid = u->eid;
    *gid = u->gid;
  } else {
    *pid = *eid = *gid = 0;
  }
}

char* EntityContainer::GetUserForUid(unsigned int uid)
{
    GenericUser *gu;
    User *u;
    const char  *username;
    char  *data;
    size_t len;

    gu = user_cont.Get(uid);
    if(gu) {
        if(strcmp(typeid(gu).name(), "User")) {
            u = static_cast<User*>(gu);
            username = u->GetUserName();
            if(username != NULL)
            {
                len = strlen(username);
                data = (char*)Malloc("username", len+1);
                if(data != NULL) {
                    strncpy(data, username, len+1);
                    return data;
                }
            }
        }
    }

    return NULL;
}

char* EntityContainer::GetNetblockForIP(uint32_t ip)
{
    Netblock *nb;
    char  *data;
    char szIPFrom[INET_ADDRSTRLEN];
    char szIPTo[INET_ADDRSTRLEN];
    size_t len;
    uint32_t nip;

    nb = static_cast<Netblock*>(lookup_interval_tree(nb_itree, ip));
    if(nb) {
        nip = htonl(nb->ip_from);
        if(inet_ntop(AF_INET, &nip, szIPFrom, sizeof(szIPFrom)) == NULL) {
            return NULL;
        }
        nip = htonl(nb->ip_to);
        if(inet_ntop(AF_INET, &nip, szIPTo, sizeof(szIPTo)) == NULL) {
            return NULL;
        }
        len = sizeof(szIPFrom)+1+sizeof(szIPTo);
        data = (char*)Malloc("netblock", len+1);
        if(data != NULL) {
            snprintf(data, len, "%s-%s", szIPFrom, szIPTo);
            return data;
        }
    }

    return NULL;
}

bool EntityContainer::GetWfaSamlFlag(unsigned int eid) {
  if(ent_id_map.count(eid) == 0) {
    return false;
  }

  Entity *ent = ent_id_map[eid];

  return ent->use_wfa_saml;
}

unsigned int EntityContainer::GetUidForAlias(unsigned int eid, const char *alias) {
  if(ent_id_map.count(eid) == 0) {
    return 0;
  }

  Entity *ent = ent_id_map[eid];

  if(!ent) {
    return 0;
  }

  if(ent->alias_map.count(alias) == 0) {
    return 0;
  }

  return ent->alias_map[alias];
}

ActionType EntityContainer::ApplyPolicyRules(unsigned int pid, Predicate &pred,
					     const char **alert_email_addr, unsigned int *rule_id,
					     bool &force_safe_search, bool &bypass_anti_malware) {
  Policy *pol;

  force_safe_search = false;
  bypass_anti_malware = false;
  *alert_email_addr = 0;
  *rule_id = 0;
  
  if(pred.uid) {
    GenericUser *gu = user_cont.Get(pred.uid);
    if(!gu) {
      bitch("Uid %u not found\n", pred.uid);
      return ACT_ERROR;
    }
    pred.SetQuotaFlag(gu->over_quota);
  } else {
    bitch("No uid in predicate\n");
  }  
  
  if((pol = static_cast<Policy*>(pol_cont.Get(pid)))) {
    pred.CalcTime(pol->tz_offset);
    force_safe_search = pol->force_safe_search;
    bypass_anti_malware = pol->bypass_anti_malware;
    return pol->ApplyRules(pred, alert_email_addr, rule_id);
  }
  return ACT_ERROR; /* policy doesn't exist */
}

ActionType EntityContainer::ApplyPolicyUrlLists(unsigned int pid, const char *uri){
  Policy *pol;

  if((pol = static_cast<Policy*>(pol_cont.Get(pid)))) {
    return pol->ApplyUrlLists(&urllist_cont, uri);
  } else {
    return ACT_ERROR; /* policy doesn't exist */
  }
}

void EntityContainer::PrintPolicy(unsigned int pid, std::ostream &os) {
  Policy *pol;
  UrlList *ul;

  if((pol = static_cast<Policy*>(pol_cont.Get(pid)))) {
    os << *pol;
    if(pol->blacklist_id)
      if((ul = static_cast<UrlList*>(urllist_cont.Get(pol->blacklist_id))))
	os << "Blacklist: " << *ul;
    if(pol->whitelist_id)
      if((ul = static_cast<UrlList*>(urllist_cont.Get(pol->whitelist_id))))
	os << "Whitelist: " << *ul;
  } else {
    os << "[unknown policy id]";
  }
}

void EntityContainer::AddEntity(Entity *ent) {
  std::vector<Netblock*>::iterator cur;
  std::vector<User*>::iterator cur_u;
  interval intv;

  DelEntity(ent->id); // delete the current object with the same id
  ent_id_map[ent->id] = ent;

  for(cur = ent->netblocks.begin(); cur != ent->netblocks.end();) {
    intv.lbound = (*cur)->ip_from;
    intv.ubound = (*cur)->ip_to;
    if(insert_interval_tree(&nb_itree, &intv, *cur)) {
      bitch("Cannot insert into interval tree: %u -> %u\n", (*cur)->ip_from, (*cur)->ip_to);
    } else {
      try {
	user_cont.Add(*cur);
	cur++;
      } catch(PolDupEx &pdx) {
	bitch("Duplicate uid for netblock %u, ignoring\n", (*cur)->GetId());
	if(remove_interval_tree(&nb_itree, &intv, 0)) {
	  bitch("Cannot delete from interval tree: %u -> %u\n", (*cur)->ip_from, (*cur)->ip_to);
	}
	delete *cur;
	cur = ent->netblocks.erase(cur);
      }
    }
  }
  
  cur_u = ent->users.begin();
  while(cur_u != ent->users.end()) {
    try {
      user_cont.Add(*cur_u);
      cur_u++;
    } catch(PolDupEx &pdx) {
      bitch("Duplicate uid for user %u, removing dups from object\n", (*cur_u)->GetId());
      delete *cur_u;
      cur_u = ent->users.erase(cur_u);
    }
  }
}

void EntityContainer::DelEntity(unsigned int eid) {
  if(ent_id_map.count(eid)) {
    std::vector<Netblock*>::iterator cur;
    std::vector<User*>::iterator cur_u;
    interval intv;
    Entity *ent = ent_id_map[eid];

    ent_id_map.erase(eid);

    for(cur = ent->netblocks.begin(); cur != ent->netblocks.end(); cur++) {
      intv.lbound = (*cur)->ip_from;
      intv.ubound = (*cur)->ip_to;
      if(remove_interval_tree(&nb_itree, &intv, 0)) {
	bitch("Cannot delete from interval tree: %u -> %u\n", (*cur)->ip_from, (*cur)->ip_to);
      }
      //      delete *cur;
      user_cont.Del((*cur)->GetId());
    }

    for(cur_u = ent->users.begin(); cur_u != ent->users.end(); cur_u++) {
      user_cont.Del((*cur_u)->GetId());
    }
    delete ent;
  }
}

unsigned int EntityContainer::GetNetblockCount() {
  return population_interval_tree(nb_itree);
}

const char* EntityContainer::GetBlockPage(unsigned int pid) {
  Policy *pol;
  
  if((pol = static_cast<Policy*>(pol_cont.Get(pid)))) {
    return pol->GetBlockPage();
  } else {
    return "Error BP02"; /* policy doesn't exist */
  }
}

const char* EntityContainer::GetPacFile(unsigned int eid) {
  if(!ent_id_map.count(eid)) {
    return "Error PF01"; /* entity doesn't exist */
  }
  return ent_id_map[eid]->PAC_file.c_str();
}

const char* EntityContainer::GetWarnPage(unsigned int pid) {
  Policy *pol;
  
  if((pol = static_cast<Policy*>(pol_cont.Get(pid)))) {
    return pol->GetWarnPage();
  } else {
    return "Error WP02"; /* policy doesn't exist -- config error? */
  }
}

const char* EntityContainer::GetPassword(unsigned int eid) {
  if(!ent_id_map.count(eid)) {
    return "Error PW01"; /* entity doesn't exist */
  }
  return ent_id_map[eid]->GetPassword();
}

Container& EntityContainer::GetPolicyContainer() {
  return pol_cont;
}

Container& EntityContainer::GetUrlListContainer() {
  return urllist_cont;
}

Container& EntityContainer::GetRuleContainer() {
  return rule_cont;
}

UserContainer& EntityContainer::GetUserContainer() {
  return user_cont;
}


Predicate::Predicate() : have_time(false), over_quota(false), is_respmod(false),
			 rep(0), uid(0), http_startline(0), http_method(0),
			 http_url(0), http_ver(0), http_statusline(0),
			 http_resver(0), http_statuscode(0), http_exposition(0) {
}

void Predicate::AddCat(CategoryType cat) {
  cat_set.insert(cat);
}

void Predicate::SetRep(int repval) {
  rep = repval;
}

void Predicate::SetUid(unsigned int uidval) {
  uid = uidval;
}

void Predicate::CalcTime(int tz_offset) {
  time_t now;
  struct tm time_str;

  have_time = true;
  now = time(0) + tz_offset;
  if(!gmtime_r(&now, &time_str)) {
    throw PolEx("gmtime_r");
  }
  
  weekday = time_str.tm_wday;
  secs_since_midnight = now % 86400;
}

/*void Predicate::SetUrl(const char *aurl) {
  url = aurl;
  }*/

void Predicate::SetHeaderData(const struct icap_state *is) {
  // Until we have random header access in snare, use workaround by mapping the
  // fixed headers.
#define HTTP_REQHDR(n,v) http_req_hdrs[ #n ] = is->encaps.http.v;
#define HTTP_RESPHDR(n,v)
#define HTTP_HDR(n, v) HTTP_REQHDR(n,v)
#include "snare/icap/http_headers.h"
#undef HTTP_HDR
#undef HTTP_RESPHDR
#undef HTTP_REQHDR
#define HTTP_REQHDR(n,v)
#define HTTP_RESPHDR(n,v) http_resp_hdrs[ #n ] = is->encaps.http.resp_ ## v;
#define HTTP_HDR(n, v) HTTP_RESPHDR(n,v)
#include "snare/icap/http_headers.h"
#undef HTTP_HDR
#undef HTTP_RESPHDR
#undef HTTP_REQHDR
  http_startline = is->encaps.http.original_startline;
  http_method = is->encaps.http.method;
  http_url = is->encaps.http.rawuri;
  http_ver = is->encaps.http.httpver;
  http_statusline = is->encaps.http.original_statusline;
  http_resver = is->encaps.http.httpresver;
  http_statuscode = is->encaps.http.statuscode;
  http_exposition = is->encaps.http.exposition;
}

void Predicate::SetHeaderDebug(const char *hdr, const char *val) {
  http_req_hdrs[hdr] = val;
}
