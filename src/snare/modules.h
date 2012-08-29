#ifndef SNARE_MODULES
#define SNARE_MODULES

#ifdef __cplusplus
extern "C" {
#endif

#include <snare/oqueue.h>
#include <snare/config.h>

typedef struct handler_interface {
	oqueue_infxn oqueuefxn;
	int (*finalfxn)(void);
	const handler_config_interface *hci;
} handler_interface;

#ifdef __cplusplus
}
#endif

#endif
