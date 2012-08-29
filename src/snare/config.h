#ifndef SNARE_CONFIG
#define SNARE_CONFIG

#include <stdint.h>

struct timeval;
struct ustring;
struct _xmlNode;
struct handlerconf;
struct handler_interface;

typedef void (*handler_free_cb)(struct handlerconf *);
typedef int (*handler_stringize_cb)(struct ustring *,const struct handlerconf *);
typedef struct handlerconf *(*handler_config_cb)(struct _xmlNode *);

typedef struct handler_config_interface {
	handler_config_cb hcb;
	handler_stringize_cb scb;
	handler_free_cb fcb;
} handler_config_interface;

int init_config(void);
int stop_config(void);

int is_reqmod_uri(const char *);
int is_respmod_uri(const char *);

uint16_t icap_port(void);
void icap_shmprefix(char *);
void icap_handler_interface(struct handler_interface *);

int stringize_snare_config(struct ustring *);

#endif
