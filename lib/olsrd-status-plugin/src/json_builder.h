/* Enhanced JSON building utilities header */

#ifndef JSON_BUILDER_H
#define JSON_BUILDER_H

#include "httpd.h"

/* Initialize a JSON buffer with error handling */
char *json_buffer_init(size_t initial_cap, http_request_t *r);

/* Initialize a JSON buffer with custom error handling */
char *json_buffer_init_with_error(size_t initial_cap, http_request_t *r, const char *error_response);

/* JSON builder macros for handlers */
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

#define JSON_APPEND_SAFE(fmt, ...) \
  do { \
    if (json_builder_append(&__jb, fmt, ##__VA_ARGS__) != 0) { \
      free(*__jb.buf); \
      send_empty_json(r); \
      return 0; \
    } \
  } while(0)

#define JSON_OBJ_START() JSON_APPEND("{")
#define JSON_OBJ_END() JSON_APPEND("}")
#define JSON_ARRAY_START() JSON_APPEND("[")
#define JSON_ARRAY_END() JSON_APPEND("]")

#define JSON_KV_STR(key, value) JSON_APPEND("\"%s\":\"%s\",", key, value ? value : "")
#define JSON_KV_INT(key, value) JSON_APPEND("\"%s\":%d,", key, value)
#define JSON_KV_LONG(key, value) JSON_APPEND("\"%s\":%ld,", key, value)
#define JSON_KV_BOOL(key, value) JSON_APPEND("\"%s\":%s,", key, value ? "true" : "false")

#define JSON_KV_STR_LAST(key, value) JSON_APPEND("\"%s\":\"%s\"", key, value ? value : "")
#define JSON_KV_INT_LAST(key, value) JSON_APPEND("\"%s\":%d", key, value)
#define JSON_KV_LONG_LAST(key, value) JSON_APPEND("\"%s\":%ld", key, value)
#define JSON_KV_BOOL_LAST(key, value) JSON_APPEND("\"%s\":%s", key, value ? "true" : "false")

#define JSON_BUILDER_CLEANUP() \
  do { \
    /* buffer is managed by caller */ \
  } while(0)

/* Forward declarations for internal functions */
typedef struct {
  char **buf;
  size_t *len;
  size_t *cap;
} json_builder_t;

void json_builder_init(json_builder_t *jb, char **buf, size_t *len, size_t *cap);
int json_builder_append(json_builder_t *jb, const char *fmt, ...);

#endif /* JSON_BUILDER_H */