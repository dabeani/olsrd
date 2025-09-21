#include "json_helpers.h"
#if defined(__GNUC__)
/* The helper functions deliberately use non-literal format strings when
 * forwarding provided fmt/args into vsnprintf/vasprintf. Silence the
 * -Wformat-nonliteral warning locally.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int json_appendf(char **bufptr, size_t *lenptr, size_t *capptr, const char *fmt, ...) {
  if (!bufptr || !lenptr || !capptr || !fmt) return -1;
  va_list ap; va_start(ap, fmt);
  va_list ap2; va_copy(ap2, ap);
  int needed = vsnprintf(NULL, 0, fmt, ap2);
  va_end(ap2);
  if (needed < 0) { va_end(ap); return -1; }
  size_t need_total = *lenptr + (size_t)needed + 1;
  if (need_total > *capptr) {
    size_t nc = *capptr ? *capptr : 1024;
    while (nc < need_total) nc *= 2;
    char *nb = realloc(*bufptr, nc);
    if (!nb) { va_end(ap); return -1; }
    *bufptr = nb; *capptr = nc;
  }
  vsnprintf((*bufptr) + *lenptr, (size_t)needed + 1, fmt, ap);
  *lenptr += (size_t)needed;
  (*bufptr)[*lenptr] = '\0';
  va_end(ap);
  return 0;
}

int json_buf_append(char **bufptr, size_t *lenptr, size_t *capptr, const char *fmt, ...) {
  if (!bufptr || !lenptr || !capptr || !fmt) return -1;
  va_list ap; char *t = NULL; int n;
  va_start(ap, fmt);
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
  n = vasprintf(&t, fmt, ap);
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
  va_end(ap);
  if (n < 0 || !t) return -1;
  if (*bufptr == NULL) {
    *capptr = (size_t)n + 128;
    *bufptr = malloc(*capptr);
    if (!*bufptr) { free(t); return -1; }
    (*bufptr)[0] = '\0'; *lenptr = 0;
  }
  if (*lenptr + (size_t)n + 1 > *capptr) {
    size_t need = *lenptr + (size_t)n + 1;
    size_t nc = *capptr * 2;
    if (nc < need) nc = need + 128;
    char *nb = realloc(*bufptr, nc);
    if (!nb) { free(t); return -1; }
    *bufptr = nb; *capptr = nc;
  }
  memcpy(*bufptr + *lenptr, t, (size_t)n);
  *lenptr += (size_t)n; (*bufptr)[*lenptr] = '\0';
  free(t);
  return 0;
}

int json_append_escaped(char **bufptr, size_t *lenptr, size_t *capptr, const char *s) {
  if (!s) return json_buf_append(bufptr, lenptr, capptr, "\"\"");
  if (json_buf_append(bufptr, lenptr, capptr, "\"") < 0) return -1;
  const unsigned char *p = (const unsigned char*)s;
  for (; *p; ++p) {
    unsigned char c = *p;
    switch (c) {
      case '"': if (json_buf_append(bufptr, lenptr, capptr, "\\\"") < 0) return -1; break;
      case '\\': if (json_buf_append(bufptr, lenptr, capptr, "\\\\") < 0) return -1; break;
      case '\b': if (json_buf_append(bufptr, lenptr, capptr, "\\b") < 0) return -1; break;
      case '\f': if (json_buf_append(bufptr, lenptr, capptr, "\\f") < 0) return -1; break;
      case '\n': if (json_buf_append(bufptr, lenptr, capptr, "\\n") < 0) return -1; break;
      case '\r': if (json_buf_append(bufptr, lenptr, capptr, "\\r") < 0) return -1; break;
      case '\t': if (json_buf_append(bufptr, lenptr, capptr, "\\t") < 0) return -1; break;
      default:
        if (c < 0x20) {
          if (json_buf_append(bufptr, lenptr, capptr, "\\u%04x", c) < 0) return -1;
        } else {
          char t[2] = { (char)c, 0 };
          if (json_buf_append(bufptr, lenptr, capptr, "%s", t) < 0) return -1;
        }
    }
  }
  if (json_buf_append(bufptr, lenptr, capptr, "\"") < 0) return -1;
  return 0;
}

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
