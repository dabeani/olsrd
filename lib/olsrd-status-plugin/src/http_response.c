/* HTTP response utilities for olsrd-status-plugin
 * Common patterns for JSON responses, error handling, and HTTP headers
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "httpd.h"
#include "http_response.h"

/* Send a JSON response with proper headers */
void send_json_response(http_request_t *r, const char *json) {
  http_send_status(r, 200, "OK");
  http_printf(r, "Content-Type: application/json; charset=utf-8\r\n\r\n");
  http_write(r, json, strlen(json));
}

/* Send an error JSON response */
void send_json_error(http_request_t *r, const char *error_msg) {
  char buf[512];
  snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}\n", error_msg);
  send_json_response(r, buf);
}

/* Send a rate limit error response */
void send_rate_limit_error(http_request_t *r) {
  http_send_status(r, 429, "Too Many Requests");
  http_printf(r, "Content-Type: application/json; charset=utf-8\r\n\r\n");
  const char *response = "{\"error\":\"rate_limited\",\"retry_after\":1}\n";
  http_write(r, response, strlen(response));
}

/* Send an empty JSON object response */
void send_empty_json(http_request_t *r) {
  send_json_response(r, "{}\n");
}

/* Send an empty JSON array response */
void send_empty_json_array(http_request_t *r) {
  send_json_response(r, "[]\n");
}