/* airos_cache.h - lightweight airos /tmp/10-all.json cache and lookup
 * Provides thread-safe lookup by IP or MAC for tx/rx/signal values.
 * Implemented with a small in-file parser (no external deps).
 */
#ifndef OLSRD_STATUS_AIROS_CACHE_H
#define OLSRD_STATUS_AIROS_CACHE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  char tx[32];
  char rx[32];
  char signal[32];
  int valid; /* 1 if fields are present */
} airos_station_t;

/* Initialize/shutdown cache (optional) */
int airos_cache_init(void);
void airos_cache_shutdown(void);

/* Refresh cache if file changed or stale; returns 0 on success, -1 on error */
int airos_cache_refresh_if_stale(void);

/* Lookup station info by IP (first match) or by MAC (first match). Return 0 and fill out on success, -1 if not found. */
int airos_lookup_by_ip(const char *ip, airos_station_t *out);
int airos_lookup_by_mac(const char *mac, airos_station_t *out);

#ifdef __cplusplus
}
#endif

#endif
