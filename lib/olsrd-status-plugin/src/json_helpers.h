/* Shared JSON buffer helpers for olsrd-status-plugin
 * Provides safe growing buffer append and JSON string escaping helpers.
 */
#ifndef JSON_HELPERS_H
#define JSON_HELPERS_H

#include <stdlib.h>
#include <stddef.h>

/* Declarations only; implementations are in json_helpers.c */
int json_appendf(char **bufptr, size_t *lenptr, size_t *capptr, const char *fmt, ...);
int json_buf_append(char **bufptr, size_t *lenptr, size_t *capptr, const char *fmt, ...);
int json_append_escaped(char **bufptr, size_t *lenptr, size_t *capptr, const char *s);

#endif /* JSON_HELPERS_H */
