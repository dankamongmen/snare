#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <libdank/utils/string.h>
#include <libdank/utils/memlimit.h>
#include "param.h"

static ParamNodeType* parse_param_value(char *param_str) {
  char *tok;
  ParamNodeType *node;
  char *param_str_start = param_str;

  if(!param_str) {
    return NULL;
  }

  node = Malloc("param_node", sizeof(ParamNodeType));
  if(!node) {
    return NULL;
  }

  tok = strsep(&param_str, "=");
  if(tok && param_str) {
    // xxx check return value
    node->param_value.name = Strdup(tok);
    node->param_value.value = Strdup(param_str);
    if(!node->param_value.name || !node->param_value.value) {
      Free(node->param_value.name);
      Free(node->param_value.value);
      Free(node);
      return NULL;
    }
  } else {
    node->param_value.name = Strdup(param_str_start);
    node->param_value.value = NULL;
    if(!node->param_value.name) {
      Free(node);
      return NULL;
    }
  }
  node->next = NULL;

  return node;
}

ParamNodeType* parse_params(const char *param_string, const char *sep) {
  char *tok;
  ParamNodeType *first = NULL, **prev = &first;
  char *param_str = Strdup(param_string);
  char *param_str_start = param_str;

  if(!param_str) {
    return NULL;
  }

  while((tok = strsep(&param_str, sep))) {
    *prev = parse_param_value(tok);
    if(!*prev) {
      // xxx handle error condition
      break;
    }
    prev = &(*prev)->next;
  }

  Free(param_str_start);
  return first;
}

enum {STATE_KEY, STATE_VALUE, STATE_VALUE_INQUOTE};
ParamNodeType* parse_params_quoteaware(const char *param_string, const char *sep) {
  char *tok = NULL, *tok_start = NULL;
  ParamNodeType *node = NULL, *first = NULL, *prev = NULL;
  char *param_str = Strdup(param_string);
  char *param_str_start = param_str;
  unsigned int state = STATE_KEY;
  int done = 0;

  if(!param_str) {
    return NULL;
  }

  tok = param_str;
  while(!done) {
    //    printf("%c (%d), %u -- ", *tok, *tok, state);
    if(!*tok) {
      done = -1;
    }
    switch(state) {
        case STATE_KEY:
            if(tok_start == NULL) {
                tok_start = tok;
            }

            if(tok_start == tok) {
                if(isspace(*tok)) {
                    //Skip initial whitespace
                    tok_start++;
                    if(!*tok_start) {
                        //The end
                        Free(param_str_start);
                        return first;
                    }
                }
            }

            if(*tok == '=') {
                //End of key - allocate node
                node = Malloc("param_node", sizeof(ParamNodeType));
                if(!node) {
                    // xxx handle error condition
                    Free(param_str_start);
                    return first;
                }
                *tok = '\0';
                node->param_value.name = Strdup(tok_start);
                node->param_value.value = NULL;
                if(!node->param_value.name) {
                    // xxx handle error condition
                    Free(node);
                    Free(param_str_start);
                    return first;
                }
                node->next = NULL;
                if(!first) {
                    first = node;
                } else {
                    prev->next = node;
                }
                prev = node;
                
                tok_start = NULL;
                state = STATE_VALUE;
            }
            break;

        case STATE_VALUE:
            if(tok_start == NULL) {
                tok_start = tok;
            }

            if(tok_start == tok) {
                if(isspace(*tok)) {
                    //Skip initial whitespace
                    tok_start++;
                    if(!*tok_start) {
                        //The end
                        Free(param_str_start);
                        return first;
                    }
                }
                else if(*tok == '"') {
                    //Value is wrapped in quotes
                    tok_start++;
                    if(!*tok_start) {
                        //The end
                        Free(param_str_start);
                        return first;
                    }
                    state = STATE_VALUE_INQUOTE;
                }
            }

            if(*tok == *sep || *tok == '\0') {
                //End of value
                *tok = '\0';
                if(node->param_value.value != NULL) {
                    //Already have value, so we probably messed up
                    // xxx handle error condition
                    Free(param_str_start);
                    return first;
                }
                node->param_value.value = Strdup(tok_start);
                if(!node->param_value.value) {
                    // xxx handle error condition
                    Free(node->param_value.name);
                    Free(node);
                    Free(param_str_start);
                    return first;
                }

                tok_start = NULL;
                state = STATE_KEY;
            }
            break;

        case STATE_VALUE_INQUOTE:
            if(tok_start == tok) {
                if(isspace(*tok)) {
                    //Skip initial whitespace
                    tok_start++;
                    if(!*tok_start) {
                        //The end
                        Free(param_str_start);
                        return first;
                    }
                }
            }
            if(*tok == '"') {
                //End of value
                *tok = '\0';
                state = STATE_VALUE;
            }
            break;
    }
    if(!done) {
      tok++;
    }
  }

  Free(param_str_start);
  return first;
}

void delete_param_list(ParamNodeType *param_list) {
  ParamNodeType *cur, *next;
  cur = param_list;
  while(cur) {
    next = cur->next;
    Free(cur->param_value.name);
    Free(cur->param_value.value);
    Free(cur);
    cur = next;
  }
}

void print_params(ParamNodeType *param_list) {
  while(param_list) {
    printf("%s = %s\n", param_list->param_value.name, param_list->param_value.value);
    param_list = param_list->next;
  }
}

int rebuild_params(ParamNodeType *param_list, ustring *u, const char *sep) {
  while(param_list) {
    if(param_list->param_value.value) {
      if(printUString(u, "%s=%s", param_list->param_value.name, param_list->param_value.value) < 0) {
	return 1;
      }
    } else {
      if(printUString(u, "%s", param_list->param_value.name) < 0) {
	return 1;
      }
    }
    param_list = param_list->next;
    if(param_list) {
      if(printUString(u, "%s", sep) < 0) {
	return 1;
      }
    }
  }
  return 0;
}

ParamNodeType* find_param(ParamNodeType *param_list, const char *name, int ignore_ws) {
  char *pname;
  while(param_list) {
    pname = param_list->param_value.name;
    if(ignore_ws) {
      while(pname && pname[0] && isspace(pname[0])) {
	pname++;
      }
    }
    if(strcmp(pname, name) == 0) {
      return param_list;
    }
    param_list = param_list->next;
  }
  return NULL;
}

void delete_param(ParamNodeType **param_list, const char *name, int ignore_ws) {
  char *pname;
  ParamNodeType *last = NULL, *cur = *param_list;
  while(cur) {
    pname = cur->param_value.name;
    if(ignore_ws) {
      while(pname && pname[0] && isspace(pname[0])) {
	pname++;
      }
    }
    if(strcmp(pname, name) == 0) {
      // We found the node with the correct name
      if(last) {
	last->next = cur->next;
      } else {
	*param_list = cur->next;
      }
      Free(cur->param_value.name);
      Free(cur->param_value.value);
      Free(cur);
    } else {
      last = cur;
    }
    cur = cur->next;
  }
}

char* get_param_value(ParamNodeType *param_list, const char *name, int ignore_ws) {
  ParamNodeType *node = find_param(param_list, name, ignore_ws);
  if(node) {
    return node->param_value.value;
  } else {
    return NULL;
  }
}

int set_param_value(ParamNodeType **param_list, const char *name, const char *value, int ignore_ws) {
  ParamNodeType *node = find_param(*param_list, name, ignore_ws);
  if(node) {
    char *newval = Strdup(value);
    if(!newval) {
      return -1;
    }
    Free(node->param_value.value);
    node->param_value.value = newval;
  } else {
    ParamNodeType *newnode;
    newnode = Malloc("param_node", sizeof(ParamNodeType));
    if(!newnode) {
      return -1;
    }
    newnode->param_value.name = Strdup(name);
    newnode->param_value.value = Strdup(value);
    if(!newnode->param_value.name || !newnode->param_value.value) {
      Free(newnode->param_value.name);
      Free(newnode->param_value.value);
      Free(newnode);
      return -1;
    }
    newnode->next = NULL;
    
    if(!*param_list) {
      *param_list = newnode;
    } else {
      ParamNodeType *cur = *param_list;
      while(cur->next) {
	cur = cur->next;
      }
      cur->next = newnode;
    }

  }
  return 0;
}
