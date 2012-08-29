#ifndef PARAM_H
#define PARAM_H

#include <libdank/objects/objustring.h>

typedef struct {
  char *name;	// also holds version/path/domain
  char *value;
} ParamValueType;

struct ParamNode {
  ParamValueType param_value;
  struct ParamNode *next;
};

typedef struct ParamNode ParamNodeType;

ParamNodeType* parse_params(const char *param_string, const char *sep);
ParamNodeType* parse_params_quoteaware(const char *param_string, const char *sep);
void delete_param_list(ParamNodeType *param_list);
void print_params(ParamNodeType *param_list);
int rebuild_params(ParamNodeType *param_list, ustring *u, const char *sep);
ParamNodeType* find_param(ParamNodeType *param_list, const char *name, int ignore_ws);
void delete_param(ParamNodeType **param_list, const char *name, int ignore_ws);
char* get_param_value(ParamNodeType *param_list, const char *name, int ignore_ws);
int set_param_value(ParamNodeType **param_list,  const char *name, const char *value, int ignore_ws);

#endif
