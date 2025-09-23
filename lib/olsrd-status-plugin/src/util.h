#ifndef OLSRD_STATUS_UTIL_H
#define OLSRD_STATUS_UTIL_H
#include <stddef.h>
int util_exec(const char *cmd, char **out, size_t *outlen);
int util_read_file(const char *path, char **out, size_t *outlen);
/* Perform a simple HTTP GET for local loopback URLs (http://127.0.0.1:PORT/path).
 * Returns 0 on success and fills *out with the response body (headers stripped).
 * Timeout is in seconds for connect+read operations.
 */
int util_http_get_url_local(const char *url, char **out, size_t *outlen, int timeout_sec);
int util_is_container(void);
/* Generic HTTP GET for arbitrary http://host[:port]/path (no TLS). Returns 0 on success.
 * For HTTPS URLs callers should fall back to an external fetch (curl) or implement TLS.
 */
int util_http_get_url(const char *url, char **out, size_t *outlen, int timeout_sec);
int util_file_exists(const char *path);
int path_exists(const char *p);
int env_is_edgerouter(void);
int env_is_linux_container(void);
int render_connections_plain(char **buf_out, size_t *len_out);
int render_connections_json(char **buf_out, size_t *len_out);

/* Allocate a buffer with initial capacity and initialize len=0, buf[0]=0 */
char *util_buffer_alloc(size_t initial_cap);

/* Reset a buffer: free existing, allocate new with initial_cap, set len=0 */
char *util_buffer_reset(char **buf, size_t *len, size_t *cap, size_t initial_cap);

#endif
