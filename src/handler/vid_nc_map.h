#ifndef VID_NC_MAP_H
#define VID_NC_MAP_H

#ifdef __cplusplus
extern "C" {
#endif

void set_vid_size(unsigned int); // max size
unsigned int get_nc(unsigned int);
void set_nc(unsigned int, unsigned int);
unsigned int get_current_vid_size(void);

#ifdef __cplusplus
}
#endif

#endif
