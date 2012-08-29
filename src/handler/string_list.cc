#include <list>
#include <string>
#include <libdank/objects/logctx.h>
#include "string_list.h"

class strlst {
public:
  strlst();
  void Add(const char *str);
  bool SubstrContains(const char *str) const;

protected:
  std::list<std::string> alst;
};

strlst::strlst() {
}

void strlst::Add(const char *str) {
  alst.push_back(str);
}

bool strlst::SubstrContains(const char *str) const {
  std::list<std::string>::const_iterator cur;
  if(!str) {
    return false;
  }
  for(cur = alst.begin(); cur != alst.end(); cur++) {
    if(strstr(str, cur->c_str())) {
      nag("[%s] matches [%s]\n", str, cur->c_str());
      return true;
    }
  }
  return false;
}

struct strlst *strlst_new() {
  try {
    return new strlst;
  } catch(...) {
    return 0;
  }
}

void strlst_delete(struct strlst *l) {
  delete l;
}

void strlst_add(struct strlst *l, const char *str) {
  l->Add(str);
}

int strlst_substr_contains(const struct strlst *l, const char *str) {
  return l->SubstrContains(str);
}
