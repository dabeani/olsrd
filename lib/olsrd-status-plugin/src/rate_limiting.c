/* Rate limiting utilities for olsrd-status-plugin */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>
#include <time.h>
#include "httpd.h"
#include "rate_limiting.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"

/* Rate limiting data structures */
struct rl_entry {
  char *key; /* heap-allocated: endpoint|ip */
  uint32_t epoch;
  time_t last_ts;
  struct rl_entry *next; /* for chaining */
};

static struct rl_entry **rl_buckets = NULL; /* array of bucket heads */
static size_t rl_buckets_len = 0; /* number of buckets */
static pthread_mutex_t rl_lock = PTHREAD_MUTEX_INITIALIZER;
static size_t rl_size = 0; /* number of entries stored */
static uint32_t rl_global_epoch = 0;
static char *g_admin_key = NULL; /* optional admin key from env or PlParam */

/* Simple in-memory diagnostics event ring buffer */
#define DIAG_LOG_CAP 256
struct diag_log_entry {
  time_t ts;
  char type[32];
  char endpoint[128];
  char client_ip[64];
  int status;
  char msg[256];
};
static struct diag_log_entry *diag_logs = NULL;
static size_t diag_logs_head = 0; /* index of oldest entry */
static size_t diag_logs_count = 0; /* number of entries stored (<= DIAG_LOG_CAP) */
static pthread_mutex_t diag_log_lock = PTHREAD_MUTEX_INITIALIZER;

/* FNV-1a 64-bit hash */
static uint64_t rl_hash(const char *s) {
  uint64_t h = UINT64_C(1469598103934665603);
  for (const unsigned char *p = (const unsigned char*)s; *p; ++p) h = (h ^ *p) * UINT64_C(1099511628211);
  return h;
}

/* Initialize rate limiting */
static int rl_ensure_initialized(size_t min_buckets) {
  if (rl_buckets && rl_buckets_len >= min_buckets) return 0;
  size_t n = 16;
  while (n < min_buckets) n <<= 1;
  struct rl_entry **nb = calloc(n, sizeof(struct rl_entry*));
  if (!nb) return -1;
  /* migrate existing entries if any */
  if (rl_buckets) {
    for (size_t i = 0; i < rl_buckets_len; ++i) {
      struct rl_entry *it = rl_buckets[i];
      while (it) {
        struct rl_entry *next = it->next;
        uint64_t h = rl_hash(it->key);
        size_t idx = (size_t)(h & (n - 1));
        it->next = nb[idx]; nb[idx] = it;
        it = next;
      }
    }
    free(rl_buckets);
  }
  rl_buckets = nb; rl_buckets_len = n;
  return 0;
}

/* Clean up stale entries */
static void rl_cleanup_stale(time_t now) {
  if (!rl_buckets) return;
  const time_t STALE = 300; /* 5 minutes */
  for (size_t i = 0; i < rl_buckets_len; ++i) {
    struct rl_entry **pp = &rl_buckets[i];
    while (*pp) {
      struct rl_entry *e = *pp;
      if (now - e->last_ts > STALE) {
        *pp = e->next;
        free(e->key); free(e);
        if (rl_size > 0) rl_size--;
      } else {
        pp = &e->next;
      }
    }
  }
}

/* Find entry by key */
static struct rl_entry *rl_find(const char *k) {
  if (!rl_buckets || rl_buckets_len == 0) return NULL;
  uint64_t h = rl_hash(k);
  size_t idx = (size_t)(h & (rl_buckets_len - 1));
  struct rl_entry *it = rl_buckets[idx];
  while (it) {
    if (strcmp(it->key, k) == 0) return it;
    it = it->next;
  }
  return NULL;
}

/* Insert new entry */
static struct rl_entry *rl_insert_new(const char *k, uint32_t epoch, time_t now) {
  if (!rl_buckets) return NULL;
  uint64_t h = rl_hash(k);
  size_t idx = (size_t)(h & (rl_buckets_len - 1));
  struct rl_entry *e = calloc(1, sizeof(*e));
  if (!e) return NULL;
  e->key = strdup(k);
  if (!e->key) { free(e); return NULL; }
  e->epoch = epoch; e->last_ts = now; e->next = rl_buckets[idx]; rl_buckets[idx] = e; rl_size++; return e;
}

/* Resize hashmap if needed */
static int rl_maybe_resize(void) {
  if (!rl_buckets) return rl_ensure_initialized(16);
  if (rl_buckets_len == 0) return rl_ensure_initialized(16);
  if (rl_size <= rl_buckets_len * 2) return 0;
  size_t newb = rl_buckets_len << 1;
  return rl_ensure_initialized(newb);
}

/* Check rate limit - returns 0 if allowed, -1 if rate-limited */
int check_rate_limit(http_request_t *r, const char *endpoint) {
  char keybuf[256];
  snprintf(keybuf, sizeof(keybuf), "%s|%s", endpoint, r->client_ip);
  time_t now = time(NULL);
  int rc = 0;

  pthread_mutex_lock(&rl_lock);
  if (!rl_buckets) {
    if (rl_ensure_initialized(64) != 0) {
      pthread_mutex_unlock(&rl_lock);
      return 0; /* fallback allow */
    }
  }
  if (rl_maybe_resize() != 0) {
    /* best-effort: ignore resize failure */
  }
  struct rl_entry *e = rl_find(keybuf);
  if (!e) {
    /* insert */
    if (!rl_insert_new(keybuf, rl_global_epoch, now)) {
      rc = 0; /* OOM: fallback allow */
    } else {
      rc = 0;
    }
  } else {
    if (e->epoch != rl_global_epoch) {
      e->epoch = rl_global_epoch; e->last_ts = now; rc = 0;
    } else {
      if (now - e->last_ts < 1) rc = -1; else { e->last_ts = now; rc = 0; }
    }
  }
  /* lazy cleanup if map grows */
  if (rl_size > rl_buckets_len * 4) rl_cleanup_stale(now);
  pthread_mutex_unlock(&rl_lock);

  return rc;
}

/* Reset rate limiting for a specific client */
void reset_rate_limit_client(const char *client_ip) {
  if (!client_ip || !*client_ip) return;

  pthread_mutex_lock(&rl_lock);
  if (rl_buckets && rl_buckets_len > 0) {
    for (size_t bi = 0; bi < rl_buckets_len; ++bi) {
      struct rl_entry **pp = &rl_buckets[bi];
      while (*pp) {
        struct rl_entry *e = *pp;
        if (e->key && strstr(e->key, client_ip)) {
          *pp = e->next;
          free(e->key); free(e);
          if (rl_size > 0) rl_size--;
        } else {
          pp = &e->next;
        }
      }
    }
  }
  pthread_mutex_unlock(&rl_lock);
}

/* Global rate limit reset */
void reset_rate_limit_global(void) {
  pthread_mutex_lock(&rl_lock);
  rl_global_epoch++;
  pthread_mutex_unlock(&rl_lock);
}

/* Set admin key for rate limiting */
void set_rate_limit_admin_key(const char *key) {
  free(g_admin_key);
  g_admin_key = key ? strdup(key) : NULL;
}

/* Get admin key for rate limiting */
const char *get_rate_limit_admin_key(void) {
  return g_admin_key;
}

/* Log diagnostic event */
void log_diagnostic_event(const char *type, const char *endpoint, const char *client_ip, int status, const char *fmt, ...) {
  if (!type) return;

  pthread_mutex_lock(&diag_log_lock);
  if (!diag_logs) {
    diag_logs = calloc(DIAG_LOG_CAP, sizeof(*diag_logs));
    if (!diag_logs) {
      pthread_mutex_unlock(&diag_log_lock);
      return;
    }
    diag_logs_head = 0;
    diag_logs_count = 0;
  }

  size_t idx;
  if (diag_logs_count < DIAG_LOG_CAP) {
    idx = (diag_logs_head + diag_logs_count) % DIAG_LOG_CAP;
    diag_logs_count++;
  } else {
    idx = diag_logs_head;
    diag_logs_head = (diag_logs_head + 1) % DIAG_LOG_CAP;
  }

  diag_logs[idx].ts = time(NULL);
  strncpy(diag_logs[idx].type, type, sizeof(diag_logs[idx].type)-1);
  diag_logs[idx].type[sizeof(diag_logs[idx].type)-1] = '\0';

  if (endpoint) {
    strncpy(diag_logs[idx].endpoint, endpoint, sizeof(diag_logs[idx].endpoint)-1);
  } else {
    diag_logs[idx].endpoint[0] = '\0';
  }
  diag_logs[idx].endpoint[sizeof(diag_logs[idx].endpoint)-1] = '\0';

  if (client_ip) {
    strncpy(diag_logs[idx].client_ip, client_ip, sizeof(diag_logs[idx].client_ip)-1);
  } else {
    diag_logs[idx].client_ip[0] = '\0';
  }
  diag_logs[idx].client_ip[sizeof(diag_logs[idx].client_ip)-1] = '\0';

  diag_logs[idx].status = status;

  if (fmt) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(diag_logs[idx].msg, sizeof(diag_logs[idx].msg), fmt, ap);
    va_end(ap);
    diag_logs[idx].msg[sizeof(diag_logs[idx].msg)-1] = '\0';
  } else {
    diag_logs[idx].msg[0] = '\0';
  }

  pthread_mutex_unlock(&diag_log_lock);
}

/* Get diagnostic logs as JSON */
char *get_diagnostic_logs_json(size_t *len_out) {
  pthread_mutex_lock(&diag_log_lock);
  size_t n = diag_logs_count;
  size_t cap = 4096 + n * 256;
  char *buf = malloc(cap);
  if (!buf) {
    pthread_mutex_unlock(&diag_log_lock);
    *len_out = 0;
    return NULL;
  }

  size_t len = 0;
  int ret = snprintf(buf + len, cap - len, "[");
  if (ret < 0) {
    free(buf);
    pthread_mutex_unlock(&diag_log_lock);
    *len_out = 0;
    return NULL;
  }
  len += (size_t)ret;

  for (size_t i = 0; i < n; ++i) {
    size_t idx = (diag_logs_head + i) % DIAG_LOG_CAP;
    struct diag_log_entry *e = &diag_logs[idx];

    /* estimate required space */
    size_t need = 300 + strlen(e->type) + strlen(e->endpoint) + strlen(e->client_ip) + strlen(e->msg);
    if (cap - len < need) {
      size_t newcap = cap * 2 + need;
      char *nb = realloc(buf, newcap);
      if (!nb) {
        free(buf);
        pthread_mutex_unlock(&diag_log_lock);
        *len_out = 0;
        return NULL;
      }
      buf = nb;
      cap = newcap;
    }

    if (i) {
      ret = snprintf(buf + len, cap - len, ",");
      if (ret < 0) {
        free(buf);
        pthread_mutex_unlock(&diag_log_lock);
        *len_out = 0;
        return NULL;
      }
      len += (size_t)ret;
    }

    ret = snprintf(buf + len, cap - len, "{\"ts\":%ld,\"type\":\"%s\",\"endpoint\":\"%s\",\"client_ip\":\"%s\",\"status\":%d,\"msg\":\"%s\"}",
                   (long)e->ts, e->type, e->endpoint, e->client_ip, e->status, e->msg[0] ? e->msg : "");
    if (ret < 0) {
      free(buf);
      pthread_mutex_unlock(&diag_log_lock);
      *len_out = 0;
      return NULL;
    }
    len += (size_t)ret;
  }

  if (cap - len < 4) {
    char *nb = realloc(buf, cap + 64);
    if (nb) {
      buf = nb;
      cap += 64;
    }
  }
  snprintf(buf + len, cap - len, "]\n");

  pthread_mutex_unlock(&diag_log_lock);
  *len_out = strlen(buf);
  return buf;
}

#pragma GCC diagnostic pop