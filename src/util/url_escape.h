#ifndef URL_ESCAPE__H
#define URL_ESCAPE__H

#ifdef __cplusplus
extern "C" {
#endif

char* normalize_url(const char *url);

int _is_unsafe_char(char ch);
void SFUT_RFC1738Unescape(char *str, size_t *unescaped_len);
void SFUT_RFC1738Escape(char *dest, const char *src, size_t src_len);
void XssEscape(char *dest, const char *src, size_t src_len);
char* XssEscapeDup(const char *src);
char* smart_url_encode(const char *url);

#ifdef __cplusplus
}
#endif

#endif
