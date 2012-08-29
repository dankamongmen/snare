#ifndef STRING_MAP_H
#define STRING_MAP_H

#ifdef __cplusplus
extern "C" {
#endif

  struct strmap;

  struct strmap *strmap_new(void);
  void strmap_delete(struct strmap *);
  void strmap_add(struct strmap*, const char*, const char*);
  const char *strmap_lookup(const struct strmap*, const char*);

#ifdef __cplusplus
}
#endif

#endif
