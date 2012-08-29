#include <map>
#include <string>
#include <libdank/objects/logctx.h>
#include "string_map.h"

// We need to rewrite the internal code in this object to either use Nick's
// radix tree in libdank or use something like libjudy. Right now, we store
// the data in a tree and do a strcasecmp() in each node. Luckily, there's
// not much we need to store in here... yet.

struct lt_case_std_str {
  bool operator()(const std::string &s1, const std::string &s2) const {
    return strcasecmp(s1.c_str(), s2.c_str()) < 0;
  }
};

class strmap {
public:
  strmap();
  void Add(const char *key, const char *val);
  const char *Lookup(const char *key) const;

protected:
  std::map<std::string, std::string, lt_case_std_str> amap;
};

strmap::strmap() {
}

void strmap::Add(const char *key, const char *val) {
  amap[key] = val;
}

const char *strmap::Lookup(const char *key) const {
  if(!amap.count(key)) {
    return 0;
  }

  std::map<std::string, std::string, lt_case_std_str>::const_iterator cur = amap.find(key);
  return cur->second.c_str();
}

struct strmap *strmap_new() {
  try {
    return new strmap;
  } catch(...) {
    return 0;
  }
}

void strmap_delete(struct strmap *m) {
  delete m;
}

void strmap_add(struct strmap *m, const char *key, const char *val) {
  m->Add(key, val);
}

const char *strmap_lookup(const struct strmap *m, const char *key) {
  return m->Lookup(key);
}
