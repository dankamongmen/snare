#include <set>
#include "u16_set.h"

class u16set {
public:
  u16set();
  bool IsEmpty();
  void Add(uint16_t);
  bool Contains(uint16_t) const;

protected:
  std::set<uint16_t> aset;
};

u16set::u16set() {
}

bool u16set::IsEmpty() {
  return aset.empty();
}

void u16set::Add(uint16_t v) {
  aset.insert(v);
}

bool u16set::Contains(uint16_t v) const {
  return aset.count(v);
}

struct u16set *u16set_new() {
  try {
    return new u16set;
  } catch(...) {
    return 0;
  }
}

void u16set_delete(struct u16set *s) {
  delete s;
}

int u16set_isempty(struct u16set *s) {
  return s->IsEmpty();
}

void u16set_add(struct u16set *s, uint16_t v) {
  s->Add(v);
}

int u16set_contains(const struct u16set *s, uint16_t v) {
  return s->Contains(v);
}
