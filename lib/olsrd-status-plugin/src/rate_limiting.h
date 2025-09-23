/* Rate limiting utilities header */

#ifndef RATE_LIMITING_H
#define RATE_LIMITING_H

#include "httpd.h"

int check_rate_limit(http_request_t *r, const char *endpoint);
void reset_rate_limit_client(const char *client_ip);
void reset_rate_limit_global(void);
void set_rate_limit_admin_key(const char *key);
const char *get_rate_limit_admin_key(void);

void log_diagnostic_event(const char *type, const char *endpoint, const char *client_ip, int status, const char *fmt, ...);
char *get_diagnostic_logs_json(size_t *len_out);

#endif /* RATE_LIMITING_H */