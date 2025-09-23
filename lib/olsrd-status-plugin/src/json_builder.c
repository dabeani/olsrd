/* Enhanced JSON building utilities for olsrd-status-plugin */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "json_helpers.h"
#include "json_builder.h"
#include "http_response.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"

/* Initialize a JSON buffer with error handling */
char *json_buffer_init(size_t initial_cap, http_request_t *r) {
  char *buf = malloc(initial_cap);
  if (!buf) {
    send_json_response(r, "{}\n");
    return NULL;
  }
  buf[0] = '\0';
  return buf;
}

/* Initialize a JSON buffer with custom error handling */
char *json_buffer_init_with_error(size_t initial_cap, http_request_t *r, const char *error_response) {
  char *buf = malloc(initial_cap);
  if (!buf) {
    send_json_response(r, error_response);
    return NULL;
  }
  buf[0] = '\0';
  return buf;
}

/* Initialize JSON builder */
void json_builder_init(json_builder_t *jb, char **buf, size_t *len, size_t *cap) {
  jb->buf = buf;
  jb->len = len;
  jb->cap = cap;
}

/* Append formatted string to JSON buffer with error handling */
int json_builder_append(json_builder_t *jb, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  va_list ap2;
  va_copy(ap2, ap);
  int needed = vsnprintf(NULL, 0, fmt, ap2);
  va_end(ap2);

  if (needed < 0) {
    va_end(ap);
    return -1;
  }

  size_t need_total = *jb->len + (size_t)needed + 1;
  if (need_total > *jb->cap) {
    size_t nc = *jb->cap ? *jb->cap : 1024;
    while (nc < need_total) nc *= 2;
    char *nb = realloc(*jb->buf, nc);
    if (!nb) {
      va_end(ap);
      return -1;
    }
    *jb->buf = nb;
    *jb->cap = nc;
  }

  vsnprintf((*jb->buf) + *jb->len, (size_t)needed + 1, fmt, ap);
  *jb->len += (size_t)needed;
  (*jb->buf)[*jb->len] = '\0';
  va_end(ap);
  return 0;
}

/* Create a JSON builder context for handlers */
#define JSON_BUILDER_INIT(buf, len, cap) \
  json_builder_t __jb; \
  json_builder_init(&__jb, &buf, &len, &cap); \
  buf = malloc(cap); \
  if (!buf) return 0; \
  buf[0] = '\0'; \
  len = 0

#define JSON_APPEND(fmt, ...) \
  do { \
    if (json_builder_append(&__jb, fmt, ##__VA_ARGS__) != 0) { \
      free(*__jb.buf); \
      return 0; \
    } \
  } while(0)

#define JSON_BUILDER_CLEANUP() \
  do { \
    /* buffer is managed by caller */ \
  } while(0)

/* Safe JSON append with cleanup on error */
#define JSON_APPEND_SAFE(fmt, ...) \
  do { \
    if (json_builder_append(&__jb, fmt, ##__VA_ARGS__) != 0) { \
      free(*__jb.buf); \
      send_empty_json(r); \
      return 0; \
    } \
  } while(0)

/* Append a JSON object start */
#define JSON_OBJ_START() JSON_APPEND("{")

/* Append a JSON object end */
#define JSON_OBJ_END() JSON_APPEND("}")

/* Append a JSON array start */
#define JSON_ARRAY_START() JSON_APPEND("[")

/* Append a JSON array end */
#define JSON_ARRAY_END() JSON_APPEND("]")

/* Append a JSON key-value pair with string value */
#define JSON_KV_STR(key, value) JSON_APPEND("\"%s\":\"%s\",", key, value ? value : "")

/* Append a JSON key-value pair with integer value */
#define JSON_KV_INT(key, value) JSON_APPEND("\"%s\":%d,", key, value)

/* Append a JSON key-value pair with long value */
#define JSON_KV_LONG(key, value) JSON_APPEND("\"%s\":%ld,", key, value)

/* Append a JSON key-value pair with boolean value */
#define JSON_KV_BOOL(key, value) JSON_APPEND("\"%s\":%s,", key, value ? "true" : "false")

/* Append a JSON key without comma (for last item) */
#define JSON_KV_STR_LAST(key, value) JSON_APPEND("\"%s\":\"%s\"", key, value ? value : "")
#define JSON_KV_INT_LAST(key, value) JSON_APPEND("\"%s\":%d", key, value)
#define JSON_KV_LONG_LAST(key, value) JSON_APPEND("\"%s\":%ld", key, value)
#define JSON_KV_BOOL_LAST(key, value) JSON_APPEND("\"%s\":%s", key, value ? "true" : "false")

#pragma GCC diagnostic pop