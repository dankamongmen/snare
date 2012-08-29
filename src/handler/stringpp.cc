#include <string>
#include <cstring>
#include <exception>
#include <libdank/utils/string.h>
#include "stringpp.h"

char* find_and_replace(const char *str, const char *str_find, const char *str_repl) {
  try {
    size_t pos;
    std::string mystr(str);
    pos = mystr.find(str_find);
    if(pos == std::string::npos) {
      return Strdup(str);
    }
    mystr.replace(pos, strlen(str_find), str_repl);
    return Strdup(mystr.c_str());
  } catch(std::bad_alloc) {
    return 0;
  }
}

char* find_and_replace_all(const char *str, const char *str_find, const char *str_repl) {
  try {
    size_t pos, cur = 0, rlen = strlen(str_repl), flen = strlen(str_find);
    std::string mystr(str);

    while((pos = mystr.find(str_find, cur)) != std::string::npos) {
      mystr.replace(pos, flen, str_repl);
      cur = pos + rlen;
    }
    return Strdup(mystr.c_str());
  } catch(std::bad_alloc) {
    return 0;
  }
}
