#ifndef APPNAME
	#error "APPNAME must be defined!"
#endif
#include <stdlib.h>
#include <snare/server.h>
#include <snare/config.h>
#include <snare/threads.h>
#include <snare/modules.h>
#include <libdank/apps/stop.h>
#include <libdank/utils/syswrap.h>
#include <libdank/utils/memlimit.h>
#include <snare/icap/compression.h>
#include <libdank/apps/initpublic.h>
#include <libdank/modules/tracing/oops.h>

#define CONFDIR		"etc/" APPNAME
#define LOGDIR		"testing/" APPNAME "log"
#define CTLSOCKET	"testing/" APPNAME "ctl"
#define LOCKFILE	"testing/" APPNAME "pid"

static app_def app = {
	.appname = APPNAME,
	.logdir = LOGDIR,
	.confdir = CONFDIR,
	.environ = NULL,
	.obnoxiousness = "A-1-A, BEACHFRONT AVENUE!",
};

int main(int argc,char **argv){
	char shmprefix[PATH_MAX];
	int ret = EXIT_FAILURE;
	handler_interface hapi;
	app_ctx appctx;
	logctx lc;

	sigemptyset(&app.blocksigs);
	sigaddset(&app.blocksigs,SIGCHLD); // FIXME unite with set_poller_sigmask
	sigaddset(&app.blocksigs,SIGURG);
	memset(&appctx,0,sizeof(appctx));
	if(app_init(&lc,&app,&appctx,argc,argv,LOCKFILE,CTLSOCKET)){
		app_stop(&app,&appctx,ret);
		return -1;
	}
	if(zlib_init()){
		goto done;
	}
	if(set_poller_sigmask()){
		goto done;
	}
	if((snarepoller = create_poller()) == NULL){
		goto done;
	}
	if(init_config()){
		goto done;
	}
	icap_shmprefix(shmprefix);
	icap_handler_interface(&hapi);
	if(init_oqueue(shmprefix,hapi.oqueuefxn)){
		goto done;
	}
	if(start_icap_servers(icap_port())){
		goto done;
	}
	if(launch_poller_thread(snarepoller)){
		goto done;
	}
	application_running();
	if(Sigwait(&appctx.waitsigs,NULL)){
		goto done;
	}
	ret = 0;

done:
	application_closing();
	ret |= close_icap_servers();
	ret |= reap_poller_thread(snarepoller);
	ret |= kill_oqueue();
	ret |= stop_config();
	ret |= destroy_poller(snarepoller);
	app_stop(&app,&appctx,ret);
}
