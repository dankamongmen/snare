#ifndef STRINGPP_H
#define STRINGPP_H

#ifdef __cplusplus
extern "C" {
#endif

  char* find_and_replace(const char *str, const char *str_find, const char *str_repl);
  char* find_and_replace_all(const char *str, const char *str_find, const char *str_repl);

#ifdef __cplusplus
}
#endif

#endif
