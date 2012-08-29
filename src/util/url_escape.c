#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <libdank/utils/string.h>
#include <libdank/utils/memlimit.h>
#include <libdank/objects/logctx.h>
#include <libdank/utils/rfc2396.h>
#include "url_escape.h"

char* normalize_url(const char *url) {
  char *buf, *ret;
  size_t ue_len, src_len;

  buf = Strdup(url);
  if(!buf) {
    return NULL;
  }

  SFUT_RFC1738Unescape(buf, &ue_len);

  src_len = strlen(buf);
  ret = Malloc("RFC1738",src_len * 3 + 1);
  if(!ret) {
    Free(buf);
    return NULL;
  }
  
  SFUT_RFC1738Escape(ret, buf, src_len);
  Free(buf);
  return ret;
}

#define HEX_STR_TO_ASCII_CHAR(str, ch)     \
{                                          \
    unsigned char ch1 = (str)[0] & 0x0f;   \
    unsigned char ch2 = (str)[1] & 0x0f;   \
    if ('9' < (str)[0])                    \
    {                                      \
        ch1 += 9;                          \
    }                                      \
    if ('9' < (str)[1])                    \
    {                                      \
        ch2 += 9;                          \
    }                                      \
    (ch) = (ch1 << 4) | ch2;               \
}


static char _hex_chars[] = "0123456789ABCDEF";

/*
 * The unsafe characters between 0x20 and 0x60, inclusive
 */
static int _unsafe_url_chars_table[] = 
{
    1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, /* 0x20 - 0x2F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, /* 0x30 - 0x3F */
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x40 - 0x4F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, /* 0x50 - 0x5F */
    1                                               /* 0x60 - 0x60 */
};


int
_is_unsafe_char(char ch)
{
    return ((ch < 0x20) ||
            (ch > 0x7A) ||
            ((ch < 0x61) && _unsafe_url_chars_table[ch - 0x20]));
}


/*--------------------------------------------------------------*\
 *
 * Name: SFUT_RFC1738Unescape
 *
 * Purpose: Unescapes the supplied string according to RFC1738.
 *          Returns the unescaped length in unescaped_len.
 *
 * Notes: The string is unescaped inline, so the supplied string
 *        must be writable memory.
 *
\*--------------------------------------------------------------*/
void
SFUT_RFC1738Unescape(char *str,
                     size_t *unescaped_len)
{
    char *p = str;
    while (*str)
    {
        if (('%' == *str) && (isxdigit(str[1])) && (isxdigit(str[2])))
        {
            HEX_STR_TO_ASCII_CHAR(str + 1, *p);
            str += 2;
        }
        else
        {
            *p = *str;
        }
        p++;
        str++;
    }
    
    *p = '\0';
    *unescaped_len = p - str + 1;

    return;
}


/*--------------------------------------------------------------*\
 *
 * Name: SFUT_RFC1738Escape
 *
 * Purpose: Escapes the supplied string according to RFC1738.
 *          Only src_len characters of src are encoded into dest.
 *
 * Notes: The dest parameter is assumed to be large enough to
 *        hold the results of escaping src_len bytes of src.
 *        To be safe, dest should be allocated (as 3 * src_len) + 1
 *
\*--------------------------------------------------------------*/
void
SFUT_RFC1738Escape(char *dest,
                   const char *src,
                   size_t src_len)
{
    size_t i = 0;

    for (i = 0 ; i < src_len; ++i)
    {
        if (_is_unsafe_char(*src))
        {
            *dest = '%';
            *(++dest) = _hex_chars[*src >> 4];
            *(++dest) = _hex_chars[*src & 0x0f];
        }
        else
        {
            *dest = *src;
        }
        src++;
        dest++;
    }
    *dest = '\0';

    return;
}

// dest needs to be 6 * strlen(src) + 1
void
XssEscape(char *dest,
	  const char *src,
	  size_t src_len)
{
    size_t i = 0;

    for (i = 0 ; i < src_len ; ++i) {
      switch(*src) {
      case '<':
	*dest++ = '&';
	*dest++ = 'l';
	*dest++ = 't';
	*dest++ = ';';
	break;
      case '>':
	*dest++ = '&';
	*dest++ = 'g';
	*dest++ = 't';
	*dest++ = ';';
	break;
      case '&':
	*dest++ = '&';
	*dest++ = 'a';
	*dest++ = 'm';
	*dest++ = 'p';
	*dest++ = ';';
	break;
      case '"':
	*dest++ = '&';
	*dest++ = 'q';
	*dest++ = 'o';
	*dest++ = 'u';
	*dest++ = 't';
	*dest++ = ';';
	break;
      case '\'':
	*dest++ = '&';
	*dest++ = '#';
	*dest++ = '0';
	*dest++ = '3';
	*dest++ = '9';
	*dest++ = ';';
	break;
      default:
	*dest++ = *src;
      }
      src++;
    }
    *dest = '\0';

    return;
}

char* XssEscapeDup(const char *src) {
  size_t len;
  char *dest;

  len = strlen(src);
  dest = Malloc("xss escape", len * 6 + 1);
  if(!dest) {
    return NULL;
  }
  XssEscape(dest, src, len);
  return dest;
}

char* smart_url_encode(const char *url) {
  char *u, *ut, *tmp, *src;
  size_t len;
  uri *pu, *cu;
  ustring ue = USTRING_INITIALIZER;

  ut = u = Strdup(url);
  if(!u) {
    return NULL;
  }

  cu = Malloc("encoded URL", sizeof(uri));
  if(!cu) {
    Free(u);
    return NULL;
  }

  SFUT_RFC1738Unescape(u, &len);

  pu = extract_uri(0, &ut);
  Free(u);
  if(!pu) {
    Free(cu);
    bitch("Could not parse out URI data\n");
    return NULL;
  }

  cu->scheme = cu->host = cu->userinfo = cu->path = cu->query = NULL;

#define ESC_URI_PART(part) \
  src = pu->part; \
  if(src) { \
    len = strlen(src); \
    tmp = Malloc("smart_url_encode: " #part, 3 * len + 1); \
    if(!tmp) { \
      free_uri(&pu); \
      free_uri(&cu); \
      return NULL; \
    } \
    SFUT_RFC1738Escape(tmp, src, len); \
    cu->part = tmp; \
  }

  // xxx this doesn't need to be a macro...
#define ESC_URI_PART_PATH \
  src = pu->path; \
  if(src) { \
    len = strlen(src); \
    tmp = Malloc("smart_url_encode: path", 3 * len + 1); \
    if(!tmp) { \
      free_uri(&pu); \
      free_uri(&cu); \
      return NULL; \
    } \
    if(len) { \
      SFUT_RFC1738Escape(tmp + 1, src, len - 1); \
      cu->path = tmp; \
    } \
  }
  
  ESC_URI_PART(scheme)
  ESC_URI_PART(host)
  ESC_URI_PART(userinfo)
  ESC_URI_PART_PATH
  ESC_URI_PART(query)

#undef ESC_URI_PART

  free_uri(&pu);
  stringize_uri(&ue, cu);
  free_uri(&cu);
  
  tmp = Strdup(ue.string);
  reset_ustring(&ue);
  
  return tmp;
}
