#include <stdio.h>
#include <strings.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <libdank/utils/string.h>
#include <libdank/objects/logctx.h>
#include <libdank/utils/memlimit.h>
#include <libxml/xmlreader.h>
#include "config_parser.h"

static ActionType getActionType(const char *szAction)
{
  ActionType action;

  if (strcasecmp((const char *) szAction, VALUE_BLOCK) == 0) {
    action = ACT_BLOCK;
  } else if (strcasecmp((const char *) szAction, VALUE_ALLOW) == 0) {
    action = ACT_ALLOW;
  } else if (strcasecmp((const char *) szAction, VALUE_WARN) == 0) {
    action = ACT_WARN;
  } else {
    action = ACT_NULL;
  }

  return action;
}

static char *getStringValue(xmlTextReaderPtr reader)
{
  const xmlChar *value;

  while (xmlTextReaderRead(reader) == 1) {
    if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
      throw PolXmlEx("Empty text element");
    }

    if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_TEXT) {
      /* Not a text field - skip */
      continue;
    }

    value = xmlTextReaderConstValue(reader);
    if (value != NULL) {
      char *ret;

      if((ret = Strdup((const char *) value)) == 0){
        throw std::bad_alloc();
      }
      return ret;
    }
    break;
  }

  throw PolXmlEx("Invalid element value");
}

static unsigned long getUnsignedLongValue(xmlTextReaderPtr reader)
{
  const xmlChar *value;
  unsigned long lValue;

  while (xmlTextReaderRead(reader) == 1) {
    if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
      throw PolXmlEx("Empty text element");
    }

    if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_TEXT) {
      /* Not a text field - skip */
      continue;
    }

    value = xmlTextReaderConstValue(reader);
    if (value != NULL) {
      lValue = strtoul((const char *) value, NULL, 10);
      return lValue;
    }
    break;
  }

  throw PolXmlEx("Invalid element value");
}

static long getLongValue(xmlTextReaderPtr reader)
{
  const xmlChar *value;
  long lValue;

  while (xmlTextReaderRead(reader) == 1) {
    if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
      throw PolXmlEx("Empty text element");
    }

    if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_TEXT) {
      /* Not a text field - skip */
      continue;
    }

    value = xmlTextReaderConstValue(reader);
    if (value != NULL) {
      lValue = strtol((const char *) value, NULL, 10);
      return lValue;
    }
    break;
  }

  throw PolXmlEx("Invalid element value");
}

static unsigned
getUnsignedIntValue(xmlTextReaderPtr reader){
	long lv;

	if((lv = getLongValue(reader)) < 0){
		throw PolXmlEx("Invalid element value");
	}
	if(static_cast<unsigned long>(lv) > static_cast<unsigned long>(UINT_MAX)){
		throw PolXmlEx("Invalid element value");
	}
	return static_cast<unsigned>(lv);
}

static int
getIntValue(xmlTextReaderPtr reader){
	long lv;

	if((lv = getLongValue(reader)) < INT_MIN){
		throw PolXmlEx("Invalid element value");
	}
	if(lv > INT_MAX){
		throw PolXmlEx("Invalid element value");
	}
	return static_cast<int>(lv);
}

static char *getCDATAValue(xmlTextReaderPtr reader)
{
  const xmlChar *value;

  while (xmlTextReaderRead(reader) == 1) {
    if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
      throw PolXmlEx("Empty text element");
    }

    if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_CDATA) {
      /* Not a CDATA field - skip */
      continue;
    }

    value = xmlTextReaderConstValue(reader);
    if (value != NULL) {
      char *ret;

      if((ret = Strdup((const char *) value)) == 0){
        throw std::bad_alloc();
      }
      return ret;
    }
    break;
  }

  throw PolXmlEx("Invalid element value");
}

static int processWebRepRuleNode(xmlTextReaderPtr reader, Rule * rule)
{
  const xmlChar *name;
  int iValue;

  while (xmlTextReaderRead(reader) == 1) {
    name = xmlTextReaderConstName(reader);
    if (name == NULL) {
      /* No element name - skip */
      continue;
    }

    if (strcasecmp((const char *) name, NODE_WEBREP_RULE) == 0
	&& xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
      /* End of webrep rule node */
      break;
    }

    if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT) {
      /* Not an element - skip */
      continue;
    }

    if (strcasecmp((const char *) name, NODE_RANGE_LOW) == 0) {
      iValue = getIntValue(reader);
      rule->SetMinRep(iValue);
    } else if (strcasecmp((const char *) name, NODE_RANGE_HIGH) == 0) {
      iValue = getIntValue(reader);
      rule->SetMaxRep(iValue);
    }
  }

  return 0;
}

static int processWebCatRuleNode(xmlTextReaderPtr reader, Rule * rule)
{
  const xmlChar *name;
  unsigned uValue;

  while (xmlTextReaderRead(reader) == 1) {
    name = xmlTextReaderConstName(reader);
    if (name == NULL) {
      /* No element name - skip */
      continue;
    }

    if (strcasecmp((const char *) name, NODE_WEBCAT_RULE) == 0
	&& xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
      /* End of webcat rule node */
      break;
    }

    if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT) {
      /* Not an element - skip */
      continue;
    }

    if (strcasecmp((const char *) name, NODE_CATEGORY_ID) == 0) {
      uValue = getUnsignedIntValue(reader);
      rule->AddCat(uValue);
    }
  }

  return 0;
}

static int processUidRuleNode(xmlTextReaderPtr reader, Rule * rule)
{
  const xmlChar *name;
  xmlChar *set_type;
  unsigned uValue;
  bool onlyfor;

  set_type = xmlTextReaderGetAttribute(reader, (const xmlChar *)ATTR_TYPE);
  if(set_type == NULL) {
    throw PolXmlEx("uid_rule element needs type attribute");
  }
  if(strcasecmp((const char*)set_type, VALUE_ALLBUT) == 0) {
    onlyfor = false;
  } else if(strcasecmp((const char*)set_type, VALUE_ONLYFOR) == 0) {
    onlyfor = true;
  } else {
    xmlFree(set_type);
    throw PolXmlEx("uid_rule type attribute needs to be " VALUE_ALLBUT " or " VALUE_ONLYFOR);
  }
  xmlFree(set_type);


  while (xmlTextReaderRead(reader) == 1) {
    name = xmlTextReaderConstName(reader);
    if (name == NULL) {
      /* No element name - skip */
      continue;
    }

    if (strcasecmp((const char *) name, NODE_UID_RULE) == 0
	&& xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
      /* End of uid rule node */
      break;
    }

    if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT) {
      /* Not an element - skip */
      continue;
    }

    if (strcasecmp((const char *) name, NODE_UID) == 0) {
      uValue = getUnsignedIntValue(reader);
      if(onlyfor) {
	rule->AddOnlyForUid(uValue);
      } else {
	rule->AddAllButUid(uValue);
      } 
    }
  }

  return 0;
}

static HTTPHeaderCheck*
processHTTPHdrRuleNode(xmlTextReaderPtr reader) {
  const xmlChar *name = NULL;
  xmlChar *hdr_type = NULL, *hdr_op = NULL;
  HeaderCheckOp opid;
  HeaderCheckType type;
  HTTPHeaderCheck *hdr_check = NULL;
  char *szHdrName = NULL;
  char *szHdrCond = NULL;

  hdr_type = xmlTextReaderGetAttribute(reader, (const xmlChar *)ATTR_TYPE);
  if(hdr_type == NULL)
  {
    throw PolXmlEx("processHTTPHdrRuleNode: Unspecified header type");
  }
  if(strcasecmp((const char*)hdr_type, "reqmod") == 0) {
    type = TYPE_REQMOD;
  } else if(strcasecmp((const char*)hdr_type, "respmod") == 0) {
    type = TYPE_RESPMOD;
  } else if(strcasecmp((const char*)hdr_type, "startline") == 0) {
    type = TYPE_STARTLINE;
  } else if(strcasecmp((const char*)hdr_type, "statusline") == 0) {
    type = TYPE_STATUSLINE;
  } else {
    xmlFree(hdr_type);
    throw PolXmlEx("processHTTPHdrRuleNode: Invalid header type");
  }
  xmlFree(hdr_type);
  hdr_op = xmlTextReaderGetAttribute(reader, (const xmlChar *)ATTR_OP);
  if(hdr_op == NULL)
  {
    throw PolXmlEx("processHTTPHdrRuleNode: Unspecified header op");
  }
  if(strcasecmp((const char*)hdr_op, "regex") == 0) {
    opid = OP_REGEX;
  } else if(strcasecmp((const char*)hdr_op, "gt") == 0) {
    opid = OP_GT;
  } else if(strcasecmp((const char*)hdr_op, "ge") == 0) {
    opid = OP_GTEQ;
  } else if(strcasecmp((const char*)hdr_op, "eq") == 0) {
    opid = OP_EQ;
  } else if(strcasecmp((const char*)hdr_op, "lt") == 0) {
    opid = OP_LT;
  } else if(strcasecmp((const char*)hdr_op, "le") == 0) {
    opid = OP_LTEQ;
  } else {
    xmlFree(hdr_op);
    throw PolXmlEx("processHTTPHdrRuleNode: Invalid header op");
  }
  xmlFree(hdr_op);

  while (xmlTextReaderRead(reader) == 1) {
    name = xmlTextReaderConstName(reader);
    if (name == NULL) {
      /* No element name - skip */
      continue;
    }

    if (strcasecmp((const char *) name, NODE_HTTPHDR_RULE) == 0
	&& xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
      /* End of httphdr rule node */
      break;
    }

    if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT) {
      /* Not an element - skip */
      continue;
    }

    if (strcasecmp((const char *)name, NODE_HTTPHDR_NAME) == 0) {
      szHdrName = getCDATAValue(reader);
    }

    if (strcasecmp((const char *)name, NODE_HTTPHDR_COND) == 0) {
      szHdrCond = getCDATAValue(reader);
    }
  }

  try {
    if (szHdrName != NULL && szHdrCond != NULL) { 
      hdr_check = new HTTPHeaderCheck();
      hdr_check->SetHeader(type, szHdrName, szHdrCond, opid);
      Free(szHdrName);
      Free(szHdrCond);
      return hdr_check;
    } else {
      throw PolXmlEx("Missing name or condition for header check");
    }
  } catch(...) {
    delete hdr_check;
    Free(szHdrName);
    Free(szHdrCond);
    throw;
  }
  delete hdr_check;
  Free(szHdrName);
  Free(szHdrCond);
  
  return 0;
}

static HeaderCheckList*
processHeaderRuleNode(xmlTextReaderPtr reader) {
  const xmlChar *name;
  xmlChar *op;
  HdrCheckObject *hdr_obj = 0;
  HeaderCheckList *lst = 0;
  bool use_or;

  try {
    op = xmlTextReaderGetAttribute(reader, (const xmlChar *)ATTR_OP);
    if(op == NULL) {
      // default to AND
      use_or = false;
    } else if(strcasecmp((const char*)op, VALUE_OR) == 0) {
      use_or = true;
    } else if(strcasecmp((const char*)op, VALUE_AND) == 0) {
      use_or = false;
    } else {
      xmlFree(op);
      throw PolXmlEx("Attribute needs to be " VALUE_OR " or " VALUE_AND);
    }
    xmlFree(op);

    lst = new HeaderCheckList;
    while (xmlTextReaderRead(reader) == 1) {
      name = xmlTextReaderConstName(reader);
      if (name == NULL) {
	/* No element name - skip */
	continue;
      }
      
      if (strcasecmp((const char *) name, NODE_HEADER_RULE) == 0
	  && xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
	/* End of node */
	break;
      }
      
      if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT) {
	/* Not an element - skip */
	continue;
      }
      
      if (strcasecmp((const char *) name, NODE_HTTPHDR_RULE) == 0) {
      	hdr_obj = processHTTPHdrRuleNode(reader);
	if(hdr_obj) {
	  try {
	    lst->AddHeaderCheckObject(hdr_obj);
	  } catch(std::bad_alloc &ba) {
	    delete hdr_obj;
	    throw PolXmlEx("Out of memory while adding header check to list");
	  }
	} else {
	  throw PolXmlEx("Null header check object");
	}
      } else if (strcasecmp((const char *) name, NODE_HEADER_RULE) == 0) {
	hdr_obj = processHeaderRuleNode(reader);
	if(hdr_obj) {
	  try {
	    lst->AddHeaderCheckObject(hdr_obj);
	  } catch(std::bad_alloc &ba) {
	    delete hdr_obj;
	    throw PolXmlEx("Out of memory while adding header list to current list");
	  }
	} else {
	  throw PolXmlEx("Null header list object");
	}
      }
    }
  } catch(...) {
    delete lst;
    throw;
  }
  if(use_or) {
    lst->UseOr();
  } else {
    lst->UseAnd();
  }
  return lst;
}

static Rule *processRuleNode(xmlTextReaderPtr reader)
{
  xmlChar *attr;
  const xmlChar *name;
  Rule *rule;
  ActionType action;
  char *szValue;
  unsigned uTimeLow = 0, uTimeHigh = 86400;
  bool bMonday = true, bTuesday = true;
  bool bWednesday = true, bThursday = true;
  bool bFriday = true, bSaturday = true, bSunday = true;
  bool quota = false;
  unsigned int id = 0;
  HeaderCheckList *hdrlst = 0;

  attr = xmlTextReaderGetAttribute(reader, (const xmlChar *) ATTR_ID);
  if (attr != NULL) {
    id = (unsigned int)strtoul((const char *) attr, NULL, 10);
    xmlFree(attr);
    if(id == 0) {
      // invalid id... need to handle this a little better
      throw PolXmlEx("Invalid id");
    }
  } else {
    // id is required
    throw PolXmlEx("Missing id");
  }

  attr = xmlTextReaderGetAttribute(reader, (const xmlChar *) ATTR_ACTION);
  if (attr == NULL) {
    throw PolXmlEx("Missing action");
  }
  action = getActionType((const char *) attr);
  xmlFree(attr);

  rule = new Rule();
  rule->SetAction(action);
  if(id) {
    rule->SetId(id);
  }

  while (xmlTextReaderRead(reader) == 1) {
    name = xmlTextReaderConstName(reader);
    if (name == NULL) {
      /* No element name - skip */
      continue;
    }
    if (strcasecmp((const char *) name, NODE_RULE) == 0
	&& xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
      /* End of rule node */
      break;
    }

    if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT) {
      /* Not an element - skip */
      continue;
    }

    if (strcasecmp((const char *) name, NODE_WEBREP_RULE) == 0) {
      processWebRepRuleNode(reader, rule);
    } else if (strcasecmp((const char *) name, NODE_WEBCAT_RULE) == 0) {
      processWebCatRuleNode(reader, rule);
    } else if (strcasecmp((const char *) name, NODE_UID_RULE) == 0) {
      processUidRuleNode(reader, rule);
    } else if (strcasecmp((const char *) name, NODE_HEADER_RULE) == 0) {
      hdrlst = processHeaderRuleNode(reader);
      try {
	rule->AddHeaderCheckList(hdrlst);
      } catch(std::bad_alloc &ba) {
	delete hdrlst;
	throw PolXmlEx("Out of memory while adding header check list");
      }
    } else if (strcasecmp((const char *) name, NODE_TIME_LOW) == 0) {
      uTimeLow = getUnsignedIntValue(reader);
    } else if (strcasecmp((const char *) name, NODE_TIME_HIGH) == 0) {
      uTimeHigh = getUnsignedIntValue(reader);
    } else if (strcasecmp((const char *) name, NODE_NOT_MONDAY) == 0) {
      bMonday = false;
    } else if (strcasecmp((const char *) name, NODE_NOT_TUESDAY) == 0) {
      bTuesday = false;
    } else if (strcasecmp((const char *) name, NODE_NOT_WEDNESDAY) == 0) {
      bWednesday = false;
    } else if (strcasecmp((const char *) name, NODE_NOT_THURSDAY) == 0) {
      bThursday = false;
    } else if (strcasecmp((const char *) name, NODE_NOT_FRIDAY) == 0) {
      bFriday = false;
    } else if (strcasecmp((const char *) name, NODE_NOT_SATURDAY) == 0) {
      bSaturday = false;
    } else if (strcasecmp((const char *) name, NODE_NOT_SUNDAY) == 0) {
      bSunday = false;
    } else if (strcasecmp((const char *) name, NODE_CHECK_QUOTA) == 0) {
      quota = true;
    } else if (strcasecmp((const char *) name, NODE_ALERT_EMAIL) == 0) {
      szValue = getStringValue(reader);
      try {
	rule->SetAlertEmailAddr(szValue);
      } catch(...) {
	Free(szValue);
	throw;
      }
      Free(szValue);
    } else if (strcasecmp((const char *) name, NODE_RULE_NAME) == 0) {
      szValue = getStringValue(reader);
      try {
	rule->SetRuleName(szValue);
      } catch(...) {
	Free(szValue);
	throw;
      }
      Free(szValue);
    }

  }

  rule->SetTimeRange(uTimeLow, uTimeHigh);
  rule->SetWeekdays(bMonday, bTuesday, bWednesday, bThursday, bFriday,
		    bSaturday, bSunday);
  rule->SetQuotaFlag(quota);

  return rule;
}

static Policy *processPolicyNode(xmlTextReaderPtr reader,
				 EntityContainer * ec)
{
  xmlChar *attr;
  const xmlChar *name;
  unsigned long lID, lValue;
  int siValue;
  Policy *policy;
  Rule *rule;
  ActionType action;
  char *szValue;

  attr = xmlTextReaderGetAttribute(reader, (const xmlChar *) ATTR_ID);
  if (attr == NULL) {
    /* No ID for policy */
    return NULL;
  }
  lID = strtoul((const char *) attr, NULL, 10);
  xmlFree(attr);

  attr = xmlTextReaderGetAttribute(reader, (const xmlChar *) ATTR_DELETE);
  if (attr != NULL) {
    /* Delete policy */
    ec->GetPolicyContainer().Del(lID);
    xmlFree(attr);
    return NULL;
  }

  attr =
      xmlTextReaderGetAttribute(reader,
				(const xmlChar *) ATTR_DEFAULTACTION);
  if (attr == NULL) {
    /* No default action for policy */
    return NULL;
  }
  action = getActionType((const char *) attr);
  xmlFree(attr);

  policy = new Policy();
  policy->SetId(lID);
  policy->SetDefaultAction(action);
  ec->GetPolicyContainer().Add(policy);

  while (xmlTextReaderRead(reader) == 1) {
    name = xmlTextReaderConstName(reader);
    if (name == NULL) {
      /* No element name - skip */
      continue;
    }

    if (strcasecmp((const char *) name, NODE_POLICY) == 0
	&& xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
      /* End of policy node */
      break;
    }

    if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT) {
      /* Not an element - skip */
      continue;
    }

    if (strcasecmp((const char *) name, NODE_BLACKLISTID) == 0) {
      lValue = getUnsignedLongValue(reader);
      if (lValue != 0) {
	policy->SetBlacklist(lValue);
      }
    } else if (strcasecmp((const char *) name, NODE_WHITELISTID) == 0) {
      lValue = getUnsignedLongValue(reader);
      policy->SetWhitelist(lValue);
    } else if (strcasecmp((const char *) name, NODE_RULE) == 0) {
      rule = processRuleNode(reader);
      if (rule != NULL) {
	policy->AddRule(rule);
	if(rule->GetId()) {
	  ec->GetRuleContainer().Add(rule);
	}
      }
    } else if (strcasecmp((const char *) name, NODE_BLOCKTEXT) == 0) {
      szValue = getCDATAValue(reader);
      try {
	policy->SetBlockPage(szValue);
      } catch(...) {
	Free(szValue);
	delete policy;
	throw;
      }
      Free(szValue);
    } else if (strcasecmp((const char *) name, NODE_WARNTEXT) == 0) {
      szValue = getCDATAValue(reader);
      try {
	policy->SetWarnPage(szValue);
      } catch(...) {
	Free(szValue);
	delete policy;
	throw;
      }
      Free(szValue);
    } else if (strcasecmp((const char *) name, NODE_TZ_OFFSET) == 0) {
      siValue = getIntValue(reader);
      policy->SetTzOffset(siValue);
    } else if (strcasecmp((const char *) name, NODE_SAFE_SEARCH) == 0) {
      policy->SetForceSafeSearch(true);
    } else if (strcasecmp((const char *) name, NODE_AM_BYPASS) == 0) {
      policy->SetBypassAntiMalware(true);
    }
  }

  return policy;
}

static Netblock *processNetblockNode(xmlTextReaderPtr reader)
{
  xmlChar *attr;
  const xmlChar *name;
  char *szValue;
  unsigned int pid = 0, gid = 0, uid;
  uint32_t ip_from, ip_to;
  bool over_quota = false;
  bool have_from = false, have_to = false, use_ntlm = false, use_ntlm_auth = false, use_cookieauth = false;
  Netblock *nb;

  attr = xmlTextReaderGetAttribute(reader, (const xmlChar *) ATTR_UID);
  if (!attr) {
    throw PolXmlEx("Netblock container needs to have a uid attribute");
  }
  // FIXME is a uid of 0 acceptable?
  // (sven) It's not... need to check for that
  uid =
      static_cast < unsigned int >(strtoul((const char *) attr, NULL, 10));
  xmlFree(attr);

  while (xmlTextReaderRead(reader) == 1) {
    name = xmlTextReaderConstName(reader);
    if (name == NULL) {
      /* No element name - skip */
      continue;
    }

    if (strcasecmp((const char *) name, NODE_NETBLOCK) == 0
	&& xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
      /* End of netblock node */
      break;
    }

    if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT) {
      /* Not an element - skip */
      continue;
    }

    if (strcasecmp((const char *) name, NODE_IP_FROM) == 0) {
      szValue = getStringValue(reader);
      if (inet_pton(AF_INET, szValue, &ip_from) <= 0) {
	Free(szValue);
	throw PolXmlEx("Invalid IP address");
      }
      Free(szValue);
      have_from = true;
    } else if (strcasecmp((const char *) name, NODE_IP_TO) == 0) {
      szValue = getStringValue(reader);
      if (inet_pton(AF_INET, szValue, &ip_to) <= 0) {
	Free(szValue);
	throw PolXmlEx("Invalid IP address");
      }
      Free(szValue);
      have_to = true;
    } else if (strcasecmp((const char *) name, NODE_POLICYID) == 0) {
      pid = static_cast < unsigned int >(getUnsignedLongValue(reader));
      if(pid == 0){
	throw PolXmlEx("Invalid Policy ID");
      }
    } else if (strcasecmp((const char *) name, NODE_GROUPID) == 0) {
      gid = static_cast < unsigned int >(getUnsignedLongValue(reader));
      if(gid == 0){
	throw PolXmlEx("Invalid Group ID");
      }
    } else if (strcasecmp((const char *) name, NODE_USE_NTLM_AUTH) == 0) {
      use_ntlm_auth = true;
    } else if (strcasecmp((const char *) name, NODE_USE_NTLM) == 0) {
      use_ntlm = true;
    } else if (strcasecmp((const char *) name, NODE_USE_COOKIEAUTH) == 0) {
      use_cookieauth = true;
    } else if (strcasecmp((const char *) name, NODE_OVER_QUOTA) == 0) {
      over_quota = true;
    }
  }

  if (!(have_from && have_to && pid && gid)) {
    throw
	PolXmlEx
	("Netblock containers need to provide ip_from, ip_to, policy_id, and group_id");
  }
  nb = new Netblock();
  nb->SetId(uid);
  nb->SetPolicyId(pid);
  nb->SetGroupId(gid);
  nb->SetFromIP(ntohl(ip_from));
  nb->SetToIP(ntohl(ip_to));
  if(use_ntlm_auth) {
    nb->UseNtlmAuth();
  }
  if(use_ntlm) {
    if(use_ntlm_auth) {
      nag("Both use_ntlm and use_ntlm_auth enabled for netblock. Ignoring use_ntlm flag.");
    } else {
      nb->UseNtlm();
    }
  }
  if(use_cookieauth) {
    nb->UseCookieAuth();
  }
  nb->SetQuotaFlag(over_quota);
  return nb;
}

static User *processUserNode(xmlTextReaderPtr reader)
{
  xmlChar *attr;
  unsigned pid = 0, gid = 0, uid;
  User *u = 0;
  char *username = 0, *pwhash = 0, *pwha1 = 0, *pwntlmhash = 0;
  bool over_quota = false;

  attr = xmlTextReaderGetAttribute(reader, (const xmlChar *) ATTR_UID);
  if (!attr) {
    throw PolXmlEx("User container needs to have a uid attribute");
  }
  // FIXME is a uid of 0 acceptable?
  // (sven) It's not... need to check for that
  uid =
      static_cast < unsigned int >(strtoul((const char *) attr, NULL, 10));
  xmlFree(attr);

  try {
    u = new User();
    while (xmlTextReaderRead(reader) == 1) {
      const xmlChar *name = xmlTextReaderConstName(reader);
      
      if (name == NULL) {
	/* No element name - skip */
	continue;
      } else if (strcasecmp((const char *) name, NODE_USER) == 0
		 && xmlTextReaderNodeType(reader) ==
		 XML_READER_TYPE_END_ELEMENT) {
	/* End of user node */
	break;
      } else if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT) {
	/* Not an element - skip */
	continue;
      } else if (strcasecmp((const char *) name, NODE_POLICYID) == 0) {
	pid = static_cast < unsigned int >(getUnsignedLongValue(reader));
	if(pid == 0){
	  throw PolXmlEx("Invalid Policy ID");
	}
      } else if (strcasecmp((const char *) name, NODE_GROUPID) == 0) {
	gid = static_cast < unsigned int >(getUnsignedLongValue(reader));
	if(gid == 0){
	  throw PolXmlEx("Invalid Group ID");
	}
      } else if (strcasecmp((const char *) name, NODE_NAME) == 0) {
	username = getStringValue(reader);
      } else if (strcasecmp((const char *) name, NODE_PASSWORD_HASH) == 0) {
	pwhash = getStringValue(reader);
      } else if (strcasecmp((const char *) name, NODE_PASSWORD_HA1) == 0) {
	pwha1 = getStringValue(reader);
      } else if (strcasecmp((const char *) name, NODE_PASSWORD_NTLMHASH) == 0) {
	pwntlmhash = getStringValue(reader);
      } else if (strcasecmp((const char *) name, NODE_OVER_QUOTA) == 0) {
	over_quota = true;
      } else if (strcasecmp((const char *) name, NODE_ALIAS) == 0) {
	char *str = 0;
	try {
	  str = getStringValue(reader);
	  u->AddAlias(str);
	  Free(str);
	} catch(...) {
	  Free(str);
	  throw;
	}
      }
    }

    if (!pid || !gid || !username || !pwhash) {
      Free(pwhash);
      Free(pwntlmhash);
      Free(username);
      Free(pwha1);
      throw PolXmlEx("User containers need to have " NODE_POLICYID ", " NODE_GROUPID
		     ", " NODE_NAME ", and " NODE_PASSWORD_HASH " elements");
    }
    u->SetPolicyId(pid);
    u->SetGroupId(gid);
    u->SetId(uid);
    u->SetQuotaFlag(over_quota);
    u->SetUserName(username);
    u->SetPasswordHash(pwhash);
    if(pwha1) {
      // This will copy pwha1 into a std::string in the user object
      u->SetPasswordHA1(pwha1);
    }
    if(pwntlmhash) {
      u->SetPasswordNtlmHash(pwntlmhash);
    }
  } catch(...) {
    Free(username);
    Free(pwhash);
    Free(pwntlmhash);
    Free(pwha1);
    delete u;
    throw;
  }
  Free(username);
  Free(pwhash);
  Free(pwntlmhash);
  Free(pwha1);
  return u;
}

static Entity *processEntityNode(xmlTextReaderPtr reader)
{
  xmlChar *attr;
  const xmlChar *name;
  unsigned long lID;
  char *szValue;
  Entity *entity;
  Netblock *nb;
  User *u;

  attr = xmlTextReaderGetAttribute(reader, (const xmlChar *) ATTR_ID);
  if (attr == NULL) {
    /* No ID for policy */
    return NULL;
  }
  lID = strtoul((const char *) attr, NULL, 10);
  xmlFree(attr);

  entity = new Entity();
  entity->SetId(lID);

  while (xmlTextReaderRead(reader) == 1) {
    name = xmlTextReaderConstName(reader);
    if (name == NULL) {
      /* No element name - skip */
      continue;
    }

    if (strcasecmp((const char *) name, NODE_ENTITY) == 0
	&& xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
      /* End of entity node */
      break;
    }

    if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT) {
      /* Not an element - skip */
      continue;
    }

    if (strcasecmp((const char *) name, NODE_NETBLOCK) == 0) {
      nb = processNetblockNode(reader);
      if (nb) {
	entity->AddNetblock(nb);
      }
    } else if (strcasecmp((const char *) name, NODE_USER) == 0) {
      u = processUserNode(reader);
      if (u) {
	entity->AddUser(u);
      }
    } else if (strcasecmp((const char *) name, NODE_PACFILE) == 0) {
      szValue = getCDATAValue(reader);
      entity->SetPacFile(szValue);
      Free(szValue);
    } else if (strcasecmp((const char *) name, NODE_ENT_PASSWORD) == 0) {
      char *str = getStringValue(reader);
      entity->SetPassword(str);
      Free(str);
    } else if (strcasecmp((const char *) name, NODE_WFA_SAML) == 0) {
      entity->UseWfaSaml();
    } else if (strcasecmp((const char *) name, NODE_AUTH_URL) == 0) {
      char *str = getStringValue(reader);
      entity->AddAuthUrl(str);
      Free(str);
    }
  }

  return entity;
}

static UrlList *processUrlListNode(xmlTextReaderPtr reader,
				   EntityContainer * ec)
{
  xmlChar *attr;
  const xmlChar *name;
  unsigned long lID;
  char *szValue;
  UrlList *urllist;

  attr = xmlTextReaderGetAttribute(reader, (const xmlChar *) ATTR_ID);
  if (attr == NULL) {
    /* No ID for policy */
    return NULL;
  }
  lID = strtoul((const char *) attr, NULL, 10);
  xmlFree(attr);

  attr = xmlTextReaderGetAttribute(reader, (const xmlChar *) ATTR_DELETE);
  if (attr != NULL) {
    /* Delete urllist */
    ec->GetUrlListContainer().Del(lID);
    xmlFree(attr);
    return NULL;
  }

  urllist = new UrlList();
  urllist->SetId(lID);
  ec->GetUrlListContainer().Add(urllist);

  while (xmlTextReaderRead(reader) == 1) {
    name = xmlTextReaderConstName(reader);
    if (name == NULL) {
      /* No element name - skip */
      continue;
    }

    if (strcasecmp((const char *) name, NODE_URLLIST) == 0
	&& xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
      /* End of urllist node */
      break;
    }

    if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT) {
      /* Not an element - skip */
      continue;
    }

    if (strcasecmp((const char *) name, NODE_URL) == 0) {
      szValue = getStringValue(reader);
      try {
	urllist->AddUrl(szValue);
      } catch(...) {
	Free(szValue);
	throw;
      }
      Free(szValue);
    }
  }

  return urllist;
}

// This should throw exceptions rather than returning a result code FIXME
static int processNode(xmlTextReaderPtr reader, EntityContainer * ec)
{
  const xmlChar *name;
  Policy *policy;
  Entity *entity;
  UrlList *urllist;

  name = xmlTextReaderConstName(reader);
  if (name == NULL) {
    return 0;
  }

  if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT) {
    /* Not an element */
    return 0;
  }

  if (strcasecmp((const char *) name, NODE_POLICY) == 0) {
    policy = processPolicyNode(reader, ec);
  } else if (strcasecmp((const char *) name, NODE_ENTITY) == 0) {
    entity = processEntityNode(reader);
    if (entity != NULL) {
      ec->AddEntity(entity);
    }
  } else if (strcasecmp((const char *) name, NODE_URLLIST) == 0) {
    urllist = processUrlListNode(reader, ec);
  } else {
    return -1; // Unknown node
  }

  return 0;
}

static void processConfigFile(xmlTextReaderPtr reader,
			      EntityContainer * ec)
{
  const xmlChar *name;
  xmlChar *attr;
  unsigned long lConfigVersion;

  while (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT) {
    /* Loop until we find first element */
    if (xmlTextReaderRead(reader) != 1) {
      /* No elements in file */
      throw PolXmlEx("No elements in file");
    }
  }

  name = xmlTextReaderConstName(reader);
  if (name == NULL || strcasecmp((const char *) name, NODE_CONFIG) != 0) {
    /* Invalid root node */
    throw PolXmlEx("Invalid root node");
  }

  attr = xmlTextReaderGetAttribute(reader, (const xmlChar *) ATTR_VERSION);
  if (attr == NULL) {
    /* No version for policy config */
    throw PolXmlEx("No version for policy config");
  }
  lConfigVersion = strtoul((const char *) attr, NULL, 10);
  xmlFree(attr);

  if(lConfigVersion > MAX_SUPPORTED_POLICY_VERSION)
  {
    /* Unsupported version */
    throw PolXmlEx("Unsupported version of policy config");
  }

  while (xmlTextReaderRead(reader) == 1) {
    if(processNode(reader, ec)){
      throw PolXmlEx("Parsing error");
    }
  }
  ec->optimizeEC();
}

int load_policy_file(const char *szFilename,EntityContainer * ec){
  xmlTextReaderPtr reader;
  int ret = 1;

  reader = xmlReaderForFile(szFilename, NULL, 0);
  if (reader != NULL) {
    try {
      ret = xmlTextReaderRead(reader);
      if (ret == 1) {
	processConfigFile(reader, ec);
      } else {
	throw PolXmlEx();
      }
    }
    catch(PolEx & pex) {
      xmlFreeTextReader(reader);
      throw pex;
    }
    xmlFreeTextReader(reader);
  } else {
    throw PolXmlEx("No reader");
  }
  return 0;
}

int load_policy_buf(const char *buf,EntityContainer * ec){
  xmlTextReaderPtr reader;
  int ret = 1;

  reader = xmlReaderForMemory(buf, strlen(buf), NULL, NULL, 0);
  if (reader != NULL) {
    try {
      ret = xmlTextReaderRead(reader);
      if (ret == 1) {
	processConfigFile(reader, ec);
      } else {
	throw PolXmlEx();
      }
    }
    catch(PolEx & pex) {
      xmlFreeTextReader(reader);
      throw pex;
    }
    xmlFreeTextReader(reader);
  } else {
    throw PolXmlEx("No reader");
  }
  return 0;
}
