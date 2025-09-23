/* HTTP response utilities header */

#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H

#include "httpd.h"

void send_json_response(http_request_t *r, const char *json);
void send_json_error(http_request_t *r, const char *error_msg);
void send_rate_limit_error(http_request_t *r);
void send_empty_json(http_request_t *r);
void send_empty_json_array(http_request_t *r);

#endif /* HTTP_RESPONSE_H */