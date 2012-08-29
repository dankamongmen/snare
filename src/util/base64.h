#ifndef BASE64_H
#define BASE64_H

char *base64_decode(const unsigned char *input, int length);
void *base64_bin_decode(const char *input, size_t *output_length);
char *base64_bin_encode(const void *input, size_t input_length);

#endif
