#ifndef U16_SET_H
#define U16_SET_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

  struct u16set;

  struct u16set *u16set_new(void);
  void u16set_delete(struct u16set*);
  int u16set_isempty(struct u16set*);
  void u16set_add(struct u16set*, uint16_t);
  int u16set_contains(const struct u16set*, uint16_t);

#ifdef __cplusplus
}
#endif

#endif
