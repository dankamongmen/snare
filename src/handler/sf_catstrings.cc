#include "sf_catstrings.h"
#include <map>

class CatStrings {
 public:
  CatStrings();
  std::map<unsigned int, const char*> cat_strings;
};

static CatStrings cat_strings;

CatStrings::CatStrings() {
#include "sf_catstrings.inc"
}

const char* get_category_name(unsigned int catid) {
  if(cat_strings.cat_strings.count(catid)) {
    return cat_strings.cat_strings[catid];
  } else {
    return "Unknown category";
  }
}
