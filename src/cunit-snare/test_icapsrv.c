#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <snare/config.h>
#include <snare/server.h>
#include <snare/poller.h>
#include <snare/threads.h>
#include <snare/icap/http.h>
#include <snare/icap/stats.h>
#include <libdank/utils/fds.h>
#include <libdank/cunit/cunit.h>
#include <libdank/utils/netio.h>
#include <libdank/utils/syswrap.h>
#include <libdank/objects/crlfreader.h>
#include <libdank/modules/fileconf/sbox.h>
#include <libdank/modules/ctlserver/ctlserver.h>

// random port so as not to conflict with running instances
#define ICAP_DEFAULT_PORT 21344

static int
common_start(void){
	struct sigaction sa;

	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	if(sigaction(SIGPIPE,&sa,NULL)){
		return -1;
	}
	if(init_fileconf("etc/snare")){
		return -1;
	}
	if(set_poller_sigmask()){
		return -1;
	}
	if((snarepoller = create_poller()) == NULL){
		return -1;
	}
	if(init_config()){
		return -1;
	}
	if(start_icap_servers(ICAP_DEFAULT_PORT)){
		return -1;
	}
	if(launch_poller_thread(snarepoller)){
		return -1;
	}
	return 0;
}

static int
test_icapconnect(void){
	struct sockaddr_in6 sina;
	struct sockaddr_in tina;
	int ret = -1,sd,z = 0;

	if(common_start()){
		goto done;
	}
	memset(&sina,0,sizeof(sina));
	sina.sin6_port = htons(ICAP_DEFAULT_PORT);
	memcpy(&sina.sin6_addr,&in6addr_loopback,sizeof(in6addr_loopback));
	sina.sin6_family = AF_INET6;
	memset(&tina,0,sizeof(tina));
	tina.sin_port = htons(ICAP_DEFAULT_PORT);
	tina.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	tina.sin_family = AF_INET;
#define CONNECT_COUNT 0x10
	printf(" Connecting to IPv4 ICAP server at loopback:%hu %d times.\n",
			ICAP_DEFAULT_PORT,CONNECT_COUNT);
	for(z = 0 ; z < CONNECT_COUNT ; ++z){
		if((sd = make_tcp_socket(PF_INET)) < 0){
			goto done;
		}
		if(Connect(sd,(struct sockaddr *)&tina,sizeof(tina))){
			Close(sd);
			goto done;
		}
		if(Close(sd)){
			goto done;
		}
	}
	printf(" Connecting to IPv6 ICAP server at loopback:%hu %d times.\n",
			ICAP_DEFAULT_PORT,CONNECT_COUNT);
	for(z = 0 ; z < CONNECT_COUNT ; ++z){
		if((sd = make_tcp_socket(PF_INET6)) < 0){
			if(errno == EAFNOSUPPORT){
				fprintf(stderr, "No local IPv6 support!\n");
				break;
			}
			goto done;
		}
		if(Connect(sd,(struct sockaddr *)&sina,sizeof(sina))){
			Close(sd);
			goto done;
		}
		if(Close(sd)){
			goto done;
		}
	}
#undef CONNECT_COUNT
	ret = 0;

done:
	printf(" Connected %d times, closing servers.\n",z);
	ret |= close_icap_servers();
	ret |= reap_poller_thread(snarepoller);
	ret |= destroy_poller(snarepoller);
	ret |= stop_config();
	ret |= stop_fileconf();
	return ret;
}

static int
test_icapstartlines(const char **slines){
	struct sockaddr_in sina;
	const char **cur;
	int ret = -1,sd;

	if(common_start()){
		goto done;
	}
	memset(&sina,0,sizeof(sina));
	sina.sin_port = htons(ICAP_DEFAULT_PORT);
	sina.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sina.sin_family = AF_INET;
	for(cur = slines ; *cur ; ++cur){
		if((sd = make_tcp_socket(PF_INET)) >= 0){
			if(Connect(sd,(struct sockaddr *)&sina,sizeof(sina)) == 0){
				printf(" Sending %s",*cur);
				if((strlen(*cur) == 0 || Writen(sd,*cur,strlen(*cur)) == 0) /*&& Writen(sd,CRLF,__builtin_strlen(CRLF)) == 0*/){
					if(Shutdown(sd,SHUT_WR) == 0){
						int i,v = 0;
						char c;

						while((i = read(sd,&c,sizeof(c))) == sizeof(c)){
							if(!v){
								printf("  ");
								v = 1;
							}
							putc(c,stdout);
							if(c == '\n'){
								v = 0;
							}
						}
						if(i == 0){
							if(Close(sd)){
								goto done;
							}
							continue; // mmm, spaghetti
						}else{
							if(i < 0){
								moan("Couldn't read reply on %d\n",sd);
							}else{
								bitch("Got %d reading on %d\n",i,sd);
							}
						}
					}
				}
			}
			Close(sd);
		}
		goto done;
	}
	ret = 0;

done:
	ret |= close_icap_servers();
	ret |= reap_poller_thread(snarepoller);
	ret |= destroy_poller(snarepoller);
	ret |= stop_config();
	ret |= stop_fileconf();
	return ret;
}

static int
test_icapstartlines_good(void){
	const char *slines[] = {
		"OPTIONS icap://localhost/tsreq-pmgr ICAP/1.0" CRLF,
		"REQMOD icap://127.0.0.1/tsreq-pmgr ICAP/1.0" CRLF,
		"REQMOD icap://localhost/tsreq-pmgr ICAP/1.0" CRLF,
		"OPTIONS icap://localhost/tsresp-pmgr ICAP/1.0" CRLF,
		"RESPMOD icap://127.0.0.1/tsresp-pmgr ICAP/1.0" CRLF,
		"RESPMOD icap://localhost/tsresp-pmgr ICAP/1.0" CRLF,
		NULL
	};

	return test_icapstartlines(slines);
}

static int
icapstartlines_bad(const char **slines){
	struct sockaddr_in sina;
	const char **cur;
	int ret = -1,sd;

	if(common_start()){
		goto done;
	}
	memset(&sina,0,sizeof(sina));
	sina.sin_port = htons(ICAP_DEFAULT_PORT);
	sina.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sina.sin_family = AF_INET;
	for(cur = slines ; *cur ; ++cur){
		if((sd = make_tcp_socket(PF_INET)) >= 0){
			if(Connect(sd,(struct sockaddr *)&sina,sizeof(sina)) == 0){
				printf(" Sending %s",*cur);
				if((strlen(*cur) == 0 || Writen(sd,*cur,strlen(*cur)) == 0)){
					int i,v = 0;
					char c;

					while((i = read(sd,&c,sizeof(c))) == sizeof(c)){
						if(!v){
							printf("  ");
							v = 1;
						}
						putc(c,stdout);
						if(c == '\n'){
							v = 0;
						}
					}
					if(i == 0){
						if(Close(sd)){
							goto done;
						}
						continue; // mmm, spaghetti
					}else{
						if(i < 0){
							moan("Couldn't read reply on %d\n",sd);
						}else{
							bitch("Got %d reading on %d\n",i,sd);
						}
					}
				}
			}
			Close(sd);
		}
		goto done;
	}
	ret = 0;

done:
	ret |= close_icap_servers();
	ret |= reap_poller_thread(snarepoller);
	ret |= destroy_poller(snarepoller);
	ret |= stop_config();
	ret |= stop_fileconf();
	return ret;
}

static int
test_icapstartlines_bad(void){
	const char *slines[] = {
		"OPTIONS icap:/// ICAP/1.0" CRLF,
		"OPTIONS icap:/// " CRLF,
		"OPTIONS icap://tsreq-pmgr " CRLF,
		"OPTIONS icap://tsresp-pmgr " CRLF,
		"REQMOD icap://127.0.0.1/tsreq-pmgrfuck ICAP/1.0" CRLF,
		"RESPMOD icap://127.0.0.1/tsreq-pmgr ICAP/1.0" CRLF,
		"REQMOD icap://localhost/tsresp-pmgr ICAP/1.0" CRLF,
		"RESPMOD icap://localhost/tsresp-pmgrfuck ICAP/1.0" CRLF,
		NULL
	};

	return icapstartlines_bad(slines);
}

static int
test_icap_stats(void){
	struct timeval tv;
	int ret = -1;

	Gettimeofday(&tv,NULL);
	if(common_start()){
		goto done;
	}
	if(init_ctlserver(CUNIT_CTLSERVER)){
		goto done;
	}
	printf(" Testing ICAP statistics (twice)...\n");
	if(ctlclient_quiet("icap_stats_dump") < 0){
		goto done;
	}
	if(ctlclient_quiet("pfd_table_dump") < 0){
		goto done;
	}
	if(ctlclient_quiet("snare_dump") < 0){
		goto done;
	}
	time_oqueue_session(&tv);
	Gettimeofday(&tv,NULL);
	time_oqueue_session(&tv);
	Gettimeofday(&tv,NULL);
	time_oqueue_session(&tv);
	Gettimeofday(&tv,NULL);
	time_oqueue_session(&tv);
	Gettimeofday(&tv,NULL);
	time_oqueue_session(&tv);
	Gettimeofday(&tv,NULL);
	ret = (ctlclient_quiet("icap_stats_dump") < 0);
	ret |= (ctlclient_quiet("pfd_table_dump") < 0);
	ret |= (ctlclient_quiet("snare_dump") < 0);

done:
	ret |= close_icap_servers();
	ret |= reap_poller_thread(snarepoller);
	ret |= destroy_poller(snarepoller);
	ret |= stop_config();
	ret |= stop_fileconf();
	ret |= stop_ctlserver();
	return ret;
}

static int
test_httplex(void){
	static const char *httphdrs[] = {
		"GET http://www.cnn.com/?scur-bp-token-1203085380-36FB7CE00B7EA8F4ABB533F872940917 HTTP/1.1" CRLF
		"Host: www.cnn.com" CRLF
		"User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.2) Gecko/20070208" CRLF
		"Iceweasel/2.0.0.2 (Debian-2.0.0.2+dfsg-3)" CRLF
		"Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5" CRLF
		"Accept-Language: en-us,en;q=0.5" CRLF
		"Accept-Encoding: gzip,deflate" CRLF
		"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7" CRLF
		"Keep-Alive: 300" CRLF
		"Proxy-Connection: keep-alive" CRLF
		"Referer: http://www.time.com/time/?scur-bp-token-1203084567-464827789B7F183E424E54C5DED3B1ED" CRLF
		"Cookie: s_vi=[CS]v1|4763110B000046D5-A170C5500000F8F[CE]; CNNid=Ga50a9079-11442-1197674763-447" CRLF
		CRLF,
		"GET http://www.cnn.com/?scur-bp-token-1203085380-36FB7CE00B7EA8F4ABB533F872940917 HTTP/1.1" CRLF
		"Host: www.cnn.com" CRLF
		"User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.2) Gecko/20070208" CRLF
		"Iceweasel/2.0.0.2 (Debian-2.0.0.2+dfsg-3)" CRLF
		"Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5" CRLF
		"Accept-Language: en-us,en;q=0.5" CRLF
		"Accept-Encoding: gzip,deflate" CRLF
		"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7" CRLF
		"Keep-Alive: 300" CRLF
		"Proxy-Connection: keep-alive" CRLF
		"Referer: http://www.time.com/time/?scur-bp-token-1203084567-464827789B7F183E424E54C5DED3B1ED" CRLF
		CRLF,
		"GET http://www.cnn.com/?scur-bp-token-1203085380-36FB7CE00B7EA8F4ABB533F872940917 HTTP/1.1" CRLF
		CRLF,
		"GET http://www.cnn.com/?scur-bp-token-1203085380-36FB7CE00B7EA8F4ABB533F872940917 HTTP/1.1" CRLF
		"Referer: http://www.time.com/time/?scur-bp-token-1203084567-464827789B7F183E424E54C5DED3B1ED" CRLF
		,
		"GET http://www.cnn.com/?scur-bp-token-1203085380-36FB7CE00B7EA8F4ABB533F872940917 HTTP/1.0" CRLF
		"User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.2) Gecko/20070208" CRLF
		"Referer: http://www.time.com/time/?scur-bp-token-1203084567-464827789B7F183E424E54C5DED3B1ED" CRLF
		CRLF,
		NULL
	},**cur;
	int ret = -1;

	if(init_icap_http()){
		fprintf(stderr," Error initializing HTTP parsing.\n");
		return -1;
	}
	for(cur = httphdrs ; *cur ; ++cur){
		icap_http_headers http;

		memset(&http,0,sizeof(http));
		if(postparse_http_reqhdr(*cur,0,strlen(*cur),&http)){
			free_icap_http_state(&http);
			goto done;
		}
		free_icap_http_state(&http);
	}
	if(stop_icap_http()){
		fprintf(stderr," Error destructing HTTP parsing.\n");
		return -1;
	}
	ret = 0;

done:
	return ret;
}

const declared_test ICAPSRV_TESTS[] = {
	{	.name = "icapconnect",
		.testfxn = test_icapconnect,
		.expected_result = EXIT_TESTSUCCESS,
		.sec_required = 0, .mb_required = 128, .disabled = 0,
	},
	{	.name = "icapstartline_good",
		.testfxn = test_icapstartlines_good,
		.expected_result = EXIT_TESTSUCCESS,
		.sec_required = 0, .mb_required = 128, .disabled = 0,
	},
	{	.name = "icapstartline_bad",
		.testfxn = test_icapstartlines_bad,
		.expected_result = EXIT_TESTSUCCESS,
		.sec_required = 0, .mb_required = 128, .disabled = 0,
	},
	{	.name = "icap_stats",
		.testfxn = test_icap_stats,
		.expected_result = EXIT_TESTSUCCESS,
		.sec_required = 0, .mb_required = 128, .disabled = 0,
	},
	{	.name = "httplex",
		.testfxn = test_httplex,
		.expected_result = EXIT_TESTSUCCESS,
		.sec_required = 0, .mb_required = 0, .disabled = 0,
	},
	{	.name = NULL,
		.testfxn = NULL,
		.expected_result = EXIT_TESTSUCCESS,
		.sec_required = 0, .mb_required = 0, .disabled = 0,
	}
};
