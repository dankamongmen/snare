#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <libdank/cunit/cunit.h>
#include <libdank/utils/memlimit.h>
#include <snare/icap/compression.h>

static int
test_deflate(void){
	long slentests[] = { 1, 255, 1600, 1024 * 1024 + 1,
	       				2 * 1024 * 1024, };
	char *inbuf = NULL;
	z_stream zstream;
	int ret = -1;
	unsigned idx;

	if(zlib_init()){
		fprintf(stderr, "Couldn't initialize zlib.\n");
		goto done;
	}
	printf(" Successfully initialized zlib helper.\n");
	for(idx = 0 ; idx < sizeof(slentests) / sizeof(*slentests) ; ++idx){
		char *outbuf,*tmp;
		int dbound;
		long b;

		if((tmp = Realloc("inbuf",inbuf,slentests[idx])) == NULL){
			goto done;
		}
		inbuf = tmp;
		for(b = 0 ; b < slentests[idx] ; ++b){
			inbuf[b] = random() % 0xff;
		}
		if(zlib_deflate_init(&zstream)){
			goto done;
		}
	       	dbound = deflateBound(&zstream,slentests[idx]);
		printf(" Bounded deflate(%ld) at %d.\n",slentests[idx],dbound);
		if((outbuf = Malloc("outbuf",dbound)) == NULL){
			zlib_deflate_free(&zstream);
			goto done;
		}
		b = 0;
		zstream.avail_out = dbound;
		zstream.next_out = (Bytef *)outbuf;
		while(b < slentests[idx]){
			long a;
			int z;

			a = (random() % 4096) + 1;
			if(a > slentests[idx] - b){
				a = slentests[idx] - b;
			}
			zstream.next_in = (Bytef *)inbuf + b;
			zstream.avail_in = a;
			b += a;
			if((z = deflate(&zstream,b < slentests[idx] ? 
					Z_NO_FLUSH : Z_FINISH)) != Z_OK){
				if(z == Z_STREAM_END){
					if(b == slentests[idx]){
						continue;
					}
				}
				zlib_deflate_free(&zstream);
				Free(outbuf);
				goto done;
			}
		}
		if(zlib_deflate_free(&zstream)){
			goto done;
		}
		Free(outbuf);
	}
	ret = 0;

done:
	Free(inbuf);
	if(zlib_destroy()){
		fprintf(stderr, "Couldn't shut down zlib.\n");
		ret = -1;
	}else{
		printf(" Successfully shut down zlib helper.\n");
	}
	return ret;
}

const declared_test ZLIB_TESTS[] = {
	{	.name = "deflate",
		.testfxn = test_deflate,
		.expected_result = EXIT_TESTSUCCESS,
		.sec_required = 20, .mb_required = 256, .disabled = 0,
	},
	{	.name = NULL,
		.testfxn = NULL,
		.expected_result = EXIT_TESTSUCCESS,
		.sec_required = 0, .mb_required = 0, .disabled = 0,
	}
};
