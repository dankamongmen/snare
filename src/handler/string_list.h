#ifndef STRING_LIST_H
#define STRING_LIST_H

#ifdef __cplusplus
extern "C" {
#endif

  struct strlst;

  struct strlst *strlst_new(void);
  void strlst_delete(struct strlst *);
  void strlst_add(struct strlst*, const char*);
  int strlst_substr_contains(const struct strlst*, const char*);

#ifdef __cplusplus
}
#endif

#endif
