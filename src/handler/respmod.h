#ifndef SRC_HANDLER_RESPMOD
#define SRC_HANDLER_RESPMOD

#include <snare/oqueue.h>

struct ustring;
struct cmd_state;
struct oqueue_key;

int init_bassdrum_respmod(void);
int stop_bassdrum_respmod(void);

verdict respmod_handler(struct oqueue_key *,icap_callback_e);

int antimalware_update_wrapper(struct cmd_state *);

int stringize_antimalware_version(struct ustring *);

#endif
