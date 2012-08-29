#include <map>
#include <list>
#include <libdank/objects/logctx.h>
#include "vid_nc_map.h"

#define DEF_VID_SIZE	1000000

struct vid_data {
  unsigned int nonce_count;
  std::list<unsigned int>::iterator lru_iter;
};

class VidMap {
public:
  VidMap();
  void SetSize(unsigned int);
  unsigned int GetNc(unsigned int);
  void SetNc(unsigned int, unsigned int);
  unsigned int GetCurrentSize() { return vnm_size; }
protected:
  void LogSizeStats();
  unsigned int size, vnm_size;
  std::map<unsigned int, struct vid_data> vid_nc_map;
  std::list<unsigned int> vid_lru_list;
};


VidMap::VidMap() : size(DEF_VID_SIZE), vnm_size(0) {
}

void VidMap::SetSize(unsigned int asize) {
  size = asize;
}

unsigned int VidMap::GetNc(unsigned int vid) {
  if(vid_nc_map.count(vid)) {
    try {
      struct vid_data &vd = vid_nc_map[vid];
      vid_lru_list.erase(vd.lru_iter);
      vid_lru_list.push_front(vid);
      vd.lru_iter = vid_lru_list.begin();
      return vd.nonce_count;
    } catch(std::bad_alloc &ba) {
      nag("Bad alloc while reusing vid\n");
      LogSizeStats();
      return 0;
    }
  } else {
    try {
      struct vid_data &vd = vid_nc_map[vid];
      if(vnm_size >= size) {
	vid_nc_map.erase(*(vid_lru_list.rbegin()));
	vid_lru_list.pop_back();
      } else {
	vnm_size++;
      }
      vid_lru_list.push_front(vid);
      vd.nonce_count = 0;
      vd.lru_iter = vid_lru_list.begin();
      return 0;
    } catch(std::bad_alloc &ba) {
      nag("Bad alloc while creating vid\n");
      LogSizeStats();
      return 0;
    }
  }
}

// Always call GetNc before
void VidMap::SetNc(unsigned int vid, unsigned int nc) {
  try {
    vid_nc_map[vid].nonce_count = nc;
  } catch(std::bad_alloc &ba) {
    nag("Bad alloc\n");
    LogSizeStats();
  }
}

void VidMap::LogSizeStats() {
  try {
    nag("%d %d\n", (unsigned int)vid_nc_map.size(), (unsigned int)vid_lru_list.size());
  } catch(...) {
    bitch("Caught exception\n");
  }
}


static VidMap vid_map;

void set_vid_size(unsigned int size) {
  vid_map.SetSize(size);
}

unsigned int get_nc(unsigned int vid) {
  return vid_map.GetNc(vid);
}

void set_nc(unsigned int vid, unsigned int nc) {
  try {
    vid_map.SetNc(vid, nc);
  } catch(...) {
    bitch("Caught exception\n");
  }
}

unsigned int get_current_vid_size() {
  return vid_map.GetCurrentSize();
}
