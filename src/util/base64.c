#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <libdank/utils/memlimit.h>
#include <libdank/objects/logctx.h>
#include <libdank/utils/string.h>
#include <string.h>
#include "base64.h"

// xxx fix type nastiness
char *base64_decode(const unsigned char *input, int length) {
  BIO *b64, *bio;
  char *buf, *inp;

  buf = Malloc("base64_decode_buf", length);
  if(!buf) {
    return NULL;
  }

  inp = Strdup((const char *)input);
  if(!inp) {
    Free(buf);
    return NULL;
  }

  memset(buf,0,length);
  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bio = BIO_new_mem_buf(inp, length);
  bio = BIO_push(b64, bio);
  BIO_read(bio, buf, length);
  BIO_free_all(bio);

  Free(inp);

  return buf;
}

void *base64_bin_decode(const char *input, size_t *output_length) {
  size_t len;
  int pad = 0;

  len = strlen(input);
  if(len == 0) {
    return NULL;
  }
  if(input[len - 1] == '=') {
    pad++;
  }
  if(len > 1 && input[len - 2] == '=') {
    pad++;
  }
  *output_length = (len - pad) * 6 / 8;
  return base64_decode((const unsigned char*)input, len);
}

char *base64_bin_encode(const void *input, size_t input_length) {
  char *output = NULL;
  BIO *b64 = NULL, *bmem = NULL;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  if(!b64) {
    bitch("Can't get BIO\n");
    goto error;
  }
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  
  bmem = BIO_new(BIO_s_mem());
  if(!bmem) {
    bitch("Can't get BIO\n");
    goto error;
  }

  b64 = BIO_push(b64, bmem);
  BIO_write(b64, (const unsigned char*)input, input_length);
  if(BIO_flush(b64) != 1) {
    bitch("Error on BIO_flush\n");
    goto error;
  }
  BIO_get_mem_ptr(b64, &bptr);
  
  if(bptr->length <= 0) {
    bitch("No output\n");
    goto error;
  }
  
  output = Malloc("base64_output", bptr->length + 1);
  if(!output) {
    goto error;
  }
  
  memcpy(output, bptr->data, bptr->length);
  output[bptr->length] = '\0';

  BIO_free_all(b64);

  return output;

 error:
  Free(output);
  if(b64) {
    // Can this be called on NULL pointers?
    BIO_free_all(b64);
  }
  if(bmem) {
    BIO_free_all(bmem);
  }
  return NULL;
}
