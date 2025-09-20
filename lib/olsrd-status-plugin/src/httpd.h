#ifndef OLSRD_STATUS_HTTPD_H
#define OLSRD_STATUS_HTTPD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct http_request {
  int fd;
  char method[8];
  char path[512];
  char query[512];
  char host[128];
  char client_ip[64];
  /* small buffered header area to batch status+headers into one syscall */
  char hdr_buf[1024];
  size_t hdr_len;
  int hdr_pending;
} http_request_t;

typedef int (*http_handler_fn)(http_request_t *r);

int http_server_start(const char *bind_ip, int port, const char *asset_root);
void http_server_stop(void);
int http_server_register_handler(const char *route, http_handler_fn fn);

void http_send_status(http_request_t *r, int code, const char *status);
void http_write(http_request_t *r, const char *buf, size_t len);
int  http_printf(http_request_t *r, const char *fmt, ...);
int  http_send_file(http_request_t *r, const char *asset_root, const char *relpath, const char *mime);

/* Access control: allow registering CIDRs or address/mask pairs; if no
 * networks registered, access is allowed for all clients. Returns 0 on
 * success, -1 on parse error. http_is_client_allowed returns 1 if the
 * client IP is allowed, 0 otherwise.
 */
int http_allow_cidr(const char *cidr_or_addr_mask);
int http_is_client_allowed(const char *client_ip);
/* Clear all registered allow-list entries. Useful when env overrides should replace config. */
void http_clear_allowlist(void);
/* Log all currently registered allow-list entries in a user-friendly form. */
void http_log_allowlist(void);
#ifdef __cplusplus
}
#endif

#endif
