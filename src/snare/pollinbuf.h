#ifndef SNARE_POLLINBUF
#define SNARE_POLLINBUF

#ifdef __cplusplus
extern "C" {
#endif

struct poller;
struct pollinbuf;
struct oqueue_key;
struct pollfd_state;

struct pollinbuf *create_pollinbuf(void)
		__attribute__ ((warn_unused_result));

typedef int (*crlfbuffer_cb)(struct pollfd_state *,char *);
typedef int (*chunkdumper_cb)(struct pollfd_state *);

int pollinbuf_cb(struct poller *,struct pollfd_state *)
		__attribute__ ((warn_unused_result));

int use_crlf_mode(struct pollinbuf *,crlfbuffer_cb)
		__attribute__ ((warn_unused_result));
void use_chunkdumper_mode(struct pollinbuf *,struct oqueue_key *,
		chunkdumper_cb,size_t);
int use_finaccept_mode(struct pollinbuf *)
		__attribute__ ((warn_unused_result));

int drain_pollinbuf(struct pollinbuf *,crlfbuffer_cb,chunkdumper_cb)
		__attribute__ ((warn_unused_result));

void free_pollinbuf(struct pollinbuf **);

#ifdef __cplusplus
}
#endif

#endif
