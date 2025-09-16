#ifndef STATUS_LOG_H
#define STATUS_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

/* Trace-level logger that writes into the plugin's ring buffer and also
 * forwards to the original stderr fd for system logs. Use like printf.
 */
void plugin_log_trace(const char *fmt, ...) __attribute__((format(printf,1,2)));

#ifdef __cplusplus
}
#endif

#endif /* STATUS_LOG_H */
