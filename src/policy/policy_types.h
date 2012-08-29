#ifndef POLICY_TYPES__H
#define POLICY_TYPES__H

typedef unsigned int CategoryType;

typedef enum {
  ACT_NULL = 0,	/* no action defined */
  ACT_ERROR,	/* something went wrong */
  ACT_ERROR_NOAUTH,	/* missing entity record */
  ACT_BLOCK,	/* block page */
  ACT_ALLOW,	/* allow page */
  ACT_WARN,	/* show warning page */
  ACT_NEED_RESPMOD	/* allow this request into the RESPMOD stage, then execute rules again */
} ActionType;

typedef enum {
  TYPE_REQMOD = 0,
  TYPE_RESPMOD,
  TYPE_STARTLINE,
  TYPE_STATUSLINE
} HeaderCheckType;

typedef enum {
  OP_REGEX = 0,
  OP_GT, /* > */
  OP_GTEQ, /* >= */
  OP_EQ, /* == */
  OP_LT, /* < */
  OP_LTEQ /* <= */
} HeaderCheckOp;

#endif
