#ifndef LIBBON_LIBBON_H
#define LIBBON_LIBBON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <antimalware/scanmapi.h> // needed for SCANMAPI_MAX_STRLEN

struct ustring;
struct libbon_bridge;

typedef struct libbon_result {
	int result;
	size_t length;
	unsigned probability;
	char name[SCANMAPI_MAX_STRLEN];
} libbon_result;

// A native bridge to the closed-source, 32-bit bontool program
struct libbon_bridge *init_libbon_bridge(const char *,const char *,const char *);
void free_libbon_bridge(struct libbon_bridge *);
int get_libbon_fd(const struct libbon_bridge *);
int get_libbon_pid(const struct libbon_bridge *);
void invalidate_libbon_wfd(struct libbon_bridge *);
int stop_libbon_bridge(struct libbon_bridge *);
int sigchld_libbon_bridge(struct libbon_bridge *);

// an mmap(2) backed by a shared memory fd
int libbon_analyze(struct libbon_bridge *,const char *,const void *,size_t,int,void *);

void *libbon_pop_analysis(struct libbon_bridge *,libbon_result *);
int libbon_rx_callback(struct libbon_bridge *);
int reconfigure_libbon_bridge(struct libbon_bridge *);
int libbon_bonware_version(struct libbon_bridge *);
int libbon_tx_available(struct libbon_bridge *);
int libbon_stringize_version(struct ustring *,struct libbon_bridge *);
int libbon_get_versions(struct libbon_bridge *,char *,char *,unsigned [3],unsigned [3]);

#ifdef __cplusplus
}
#endif

#endif
