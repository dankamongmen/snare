#include <snare/config.h>
#include <snare/poller.h>
#include <snare/server.h>
#include <snare/threads.h>
#include <libdank/cunit/cunit.h>
#include <libdank/objects/objustring.h>
#include <libdank/modules/fileconf/sbox.h>
#include <libdank/modules/ctlserver/ctlserver.h>

static int
test_snareprimaryconfig(void){
	ustring u = USTRING_INITIALIZER;
	int ret = -1;

	if(init_fileconf("etc/snare")){
		return -1;
	}
	if((snarepoller = create_poller()) == NULL){
		goto done;
	}
	if(init_config()){
		goto done;
	}
	if(stringize_snare_config(&u)){
		goto done;
	}
	printf(" %s\n",u.string);
	ret = 0;

done:
	ret |= stop_config();
	ret |= destroy_poller(snarepoller);
	ret |= stop_fileconf();
	reset_ustring(&u);
	return ret;
}

const declared_test SNARECONF_TESTS[] = {
	{	.name = "snareprimaryconfig",
		.testfxn = test_snareprimaryconfig,
		.expected_result = EXIT_TESTSUCCESS,
		.sec_required = 0, .mb_required = 0, .disabled = 0,
	},
	{	.name = NULL,
		.testfxn = NULL,
		.expected_result = EXIT_TESTSUCCESS,
		.sec_required = 0, .mb_required = 0, .disabled = 0,
	}
};

const char *CUNIT_EXTENSIONS[] = {
	"SNARECONF_TESTS",
	"ICAPSRV_TESTS",
	"ZLIB_TESTS",
	NULL
};
