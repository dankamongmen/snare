#ifndef CONFIG_PARSER__H
#define CONFIG_PARSER__H

#include "policy.h"

#define NODE_CONFIG         "policymgr_config"
#define NODE_POLICY         "policy"
#define NODE_ENTITY         "entity"
#define NODE_URLLIST        "urllist"
#define NODE_BLACKLISTID    "blacklist_id"
#define NODE_WHITELISTID    "whitelist_id"
#define NODE_RULE           "rule"
#define NODE_WEBREP_RULE    "webrep_rule"
#define NODE_WEBCAT_RULE    "webcat_rule"
#define NODE_RANGE_LOW      "range_low"
#define NODE_RANGE_HIGH     "range_high"
#define NODE_TIME_LOW       "time_low"
#define NODE_TIME_HIGH      "time_high"
#define NODE_NOT_MONDAY     "not_monday"
#define NODE_NOT_TUESDAY    "not_tuesday"
#define NODE_NOT_WEDNESDAY  "not_wednesday"
#define NODE_NOT_THURSDAY   "not_thursday"
#define NODE_NOT_FRIDAY     "not_friday"
#define NODE_NOT_SATURDAY   "not_saturday"
#define NODE_NOT_SUNDAY     "not_sunday"
#define NODE_CATEGORY_ID    "category_id"
#define NODE_UID_RULE       "uid_rule"
#define NODE_UID            "uid"
#define NODE_HEADER_RULE    "header_rule"
#define NODE_HTTPHDR_RULE   "http_header"
#define NODE_HTTPHDR_NAME   "hdrname"
#define NODE_HTTPHDR_COND   "hdrcond"
#define NODE_URL            "url"
#define NODE_BLOCKTEXT      "block_text"
#define NODE_WARNTEXT       "warn_text"
#define NODE_WFA_SAML       "wfa_saml"
#define NODE_AUTH_URL       "auth_url"
#define NODE_NETBLOCK       "netblock"
#define NODE_USE_NTLM       "use_ntlm"
#define NODE_USE_NTLM_AUTH  "use_ntlm_auth"
#define NODE_USE_COOKIEAUTH "use_cookieauth"
#define NODE_IP_FROM        "ip_from"
#define NODE_IP_TO          "ip_to"
#define NODE_POLICYID       "policy_id"
#define NODE_GROUPID        "group_id"
#define NODE_USER           "user"
#define NODE_NAME           "name"
#define NODE_ALIAS          "alias"
#define NODE_PASSWORD_HASH  "password_hash"
#define NODE_PASSWORD_HA1   "password_ha1"
#define NODE_PASSWORD_NTLMHASH  "password_ntlmhash"
#define NODE_ALERT_EMAIL    "alert_email"
#define NODE_RULE_NAME      "rule_name"
#define NODE_PACFILE        "pac_file"
#define NODE_TZ_OFFSET      "tz_offset"
#define NODE_SAFE_SEARCH    "safe_search"
#define NODE_AM_BYPASS      "am_bypass"
#define NODE_ENT_PASSWORD   "ent_password"
#define NODE_OVER_QUOTA     "over_quota"
#define NODE_CHECK_QUOTA    "check_quota"

#define ATTR_VERSION        "version"
#define ATTR_ID             "id"
#define ATTR_UID            "uid"
#define ATTR_DEFAULTACTION  "default_action"
#define ATTR_ACTION         "action"
#define ATTR_DELETE         "delete"
#define ATTR_TYPE           "type"
#define ATTR_OP             "op"

#define VALUE_BLOCK         "block"
#define VALUE_ALLOW         "allow"
#define VALUE_WARN          "warn"

#define VALUE_ALLBUT        "all_but"
#define VALUE_ONLYFOR       "only_for"

#define VALUE_OR            "or"
#define VALUE_AND           "and"

int load_policy_file(const char *,EntityContainer *);
int load_policy_buf(const char *,EntityContainer *);

#endif