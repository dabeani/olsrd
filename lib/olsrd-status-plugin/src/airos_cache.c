#include "airos_cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/* Simple in-memory storage: dynamic arrays of entries. Each entry holds ip and mac keys and station data. */
typedef struct {
  char ip[64];
  char mac[64];
  airos_station_t info;
} airos_entry_t;

static airos_entry_t *g_entries = NULL;
static size_t g_entries_n = 0;
static size_t g_entries_cap = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static time_t g_mtime = 0;

/* Utility: read whole file into buffer */
static int read_file(const char *path, char **out, size_t *out_n, time_t *out_mtime) {
  if (!path || !out || !out_n) return -1;
  FILE *f = fopen(path, "rb");
  if (!f) return -1;
  if (out_mtime) {
    struct stat st;
    if (fstat(fileno(f), &st) == 0) {
      *out_mtime = st.st_mtime;
    } else {
      *out_mtime = 0;
    }
  }
  if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
  long sz = ftell(f); if (sz < 0) { fclose(f); return -1; }
  if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
  char *b = malloc((size_t)sz + 1);
  if (!b) { fclose(f); return -1; }
  size_t r = fread(b, 1, (size_t)sz, f);
  fclose(f);
  b[r] = '\0'; *out = b; *out_n = r; return 0;
}

/* Very small, tolerant JSON helpers: find next token/pair in an object; not a full parser
 * We'll look for station objects under connections arrays; behavior tuned to expected airos format.
 */

/* Skip whitespace */
static const char *skipws(const char *p, const char *end) {
  while (p && p < end && *p && isspace((unsigned char)*p)) p++;
  return p;
}

/* Extract a quoted JSON string starting at p (pointing at '"'). Returns pointer after closing quote, and fills dst (bounded) with content. */
static const char *extract_quoted(const char *p, const char *end, char *dst, size_t dstsz) {
  if (!p || p >= end || *p != '"') return NULL;
  p++; const char *s = p; char *o = dst; size_t left = dstsz ? dstsz - 1 : 0;
  while (p && p < end && *p) {
    if (*p == '\\' && (p+1) < end) {
      p += 2; if (left) { *o++ = *s; left--; } s = p; continue;
    }
    if (*p == '"') break;
    p++;
  }
  if (!p || p >= end || *p != '"') return NULL;
  size_t L = (size_t)(p - s);
  if (L >= dstsz) L = dstsz - 1;
  if (dstsz) memcpy(dst, s, L), dst[L] = '\0';
  return p+1;
}

/* Find a JSON key in a limited object region: returns pointer to value start or NULL. */
static const char *find_key(const char *obj_b, const char *obj_e, const char *key) {
  const char *p = obj_b;
  size_t klen = strlen(key);
  while (p && p < obj_e) {
    p = strchr(p, '"'); if (!p || p >= obj_e) break;
    const char *q = p+1; const char *qend = strchr(q, '"'); if (!qend || qend >= obj_e) break;
    size_t sl = (size_t)(qend - q);
    if (sl == klen && strncmp(q, key, klen) == 0) {
      /* move to ':' */
      const char *c = qend + 1;
      while (c < obj_e && *c && *c != ':')
        c++;
      if (c >= obj_e || *c != ':') {
        return NULL;
      }
      c++;
      return skipws(c, obj_e);
    }
    p = qend + 1;
  }
  return NULL;
}

/* Parse a station object between st..en, extract mac, tx, rx, signal into provided buffers (bounded). Returns 0 on success. */
static int parse_station_obj(const char *st, const char *en, char *macbuf, size_t macsz, char *txbuf, size_t txsz, char *rxbuf, size_t rxsz, char *sigbuf, size_t sigsz) {
  macbuf[0]=txbuf[0]=rxbuf[0]=sigbuf[0]='\0';
  const char *v;
  /* mac */ v = find_key(st, en, "mac"); if (v && *v=='\"') { const char *next = extract_quoted(v, en, macbuf, macsz); if (!next) macbuf[0]=0; }
  /* tx */ v = find_key(st, en, "tx"); if (v) { char num[32]; size_t i=0; while (v<en && *v && (i+1)<sizeof(num) && (isdigit((unsigned char)*v) || *v=='-' || *v=='+')) num[i++]=*v++; num[i]=0; if(i) { if(txsz) strncpy(txbuf,num,txsz-1), txbuf[txsz-1]=0; } }
  /* rx */ v = find_key(st, en, "rx"); if (v) { char num[32]; size_t i=0; while (v<en && *v && (i+1)<sizeof(num) && (isdigit((unsigned char)*v) || *v=='-' || *v=='+')) num[i++]=*v++; num[i]=0; if(i) { if(rxsz) strncpy(rxbuf,num,rxsz-1), rxbuf[rxsz-1]=0; } }
  /* signal (number or string) */ v = find_key(st, en, "signal"); if (v) {
    const char *p = skipws(v, en);
    if (p && p < en && *p == '"') { extract_quoted(p, en, sigbuf, sigsz); }
    else { char num[32]; size_t i=0; while (p<en && *p && (i+1)<sizeof(num) && (isdigit((unsigned char)*p) || *p=='-' || *p=='+')) num[i++]=*p++; num[i]=0; if(i) { if(sigsz) strncpy(sigbuf,num,sigsz-1), sigbuf[sigsz-1]=0; } }
  }
  return 0;
}

/* Scan buffer for station objects inside connections arrays and populate entries. This is conservative and bounded. */
static void parse_airos(const char *buf, size_t n) {
  const char *end = buf + n;
  const char *p = buf;
  while ((p = strstr(p, "\"connections\"")) != NULL) {
    /* find '[' after connections */
    const char *br = strchr(p, '['); if (!br || br >= end) { p += 12; continue; }
    /* find matching ] */
    const char *ebr = br; int depth = 0;
    while (ebr < end && *ebr) {
      if (*ebr == '[') depth++; else if (*ebr == ']') { depth--; if (depth == 0) { ebr++; break; } }
      ebr++;
    }
    if (!ebr || ebr <= br) { p = br + 1; continue; }
    /* iterate station objects inside br..ebr */
    const char *st = br; while (st < ebr && *st) {
      if (*st == '{') {
        const char *q = st; int d = 0; while (q < ebr) { if (*q == '{') d++; else if (*q == '}') { d--; if (d == 0) { q++; break; } } q++; }
        if (q <= st) break;
        char mac[64] = {0}, tx[32] = {0}, rx[32] = {0}, sig[32] = {0};
        parse_station_obj(st, q, mac, sizeof(mac), tx, sizeof(tx), rx, sizeof(rx), sig, sizeof(sig));
        /* Find IP strings within station object by searching for quoted tokens that look like IPv4 addresses */
        const char *ipcur = st; char iptok[64] = {0}; char foundip[64] = {0};
        while (ipcur < q) {
          const char *qq = strchr(ipcur, '"'); if (!qq || qq >= q) break;
          const char *qe = strchr(qq+1, '"'); if (!qe || qe >= q) break;
          size_t L = (size_t)(qe - (qq+1)); if (L < sizeof(iptok)) {
            memcpy(iptok, qq+1, L); iptok[L]=0;
            /* crude IPv4 check */
            int dots = 0; for (size_t i=0;i<strlen(iptok);++i) if (iptok[i]=='.') dots++;
            if (dots == 3) { strncpy(foundip, iptok, sizeof(foundip)-1); foundip[sizeof(foundip)-1]=0; }
          }
          ipcur = qe + 1;
        }
        /* store entry: we may have mac and/or ip */
        if (mac[0] || foundip[0]) {
          /* append */
          if (g_entries_n + 1 > g_entries_cap) {
            size_t newcap = g_entries_cap ? g_entries_cap * 2 : 64;
            airos_entry_t *ne = realloc(g_entries, newcap * sizeof(*ne));
            if (!ne) {
              break;
            }
            g_entries = ne;
            g_entries_cap = newcap;
          }
          airos_entry_t *ent = &g_entries[g_entries_n++];
          ent->ip[0]=ent->mac[0]=0; ent->info.valid = 0;
          if (foundip[0]) strncpy(ent->ip, foundip, sizeof(ent->ip)-1);
          if (mac[0]) strncpy(ent->mac, mac, sizeof(ent->mac)-1);
          if (tx[0] || rx[0] || sig[0]) { ent->info.valid = 1; if (tx[0]) strncpy(ent->info.tx, tx, sizeof(ent->info.tx)-1); if (rx[0]) strncpy(ent->info.rx, rx, sizeof(ent->info.rx)-1); if (sig[0]) strncpy(ent->info.signal, sig, sizeof(ent->info.signal)-1); }
        }
        st = q; continue;
      }
      st++;
    }
    p = ebr;
  }
}

int airos_cache_init(void) { return 0; }
void airos_cache_shutdown(void) { pthread_mutex_lock(&g_lock); if (g_entries) free(g_entries); g_entries = NULL; g_entries_n = g_entries_cap = 0; pthread_mutex_unlock(&g_lock); }

int airos_cache_refresh_if_stale(void) {
  char *buf = NULL; size_t n = 0; time_t mtime = 0;
  if (read_file("/tmp/10-all.json", &buf, &n, &mtime) != 0) return -1;
  pthread_mutex_lock(&g_lock);
  if (mtime == g_mtime) { pthread_mutex_unlock(&g_lock); free(buf); return 0; }
  /* rebuild entries */
  if (g_entries) { free(g_entries); g_entries = NULL; g_entries_n = g_entries_cap = 0; }
  /* parse buffer */
  parse_airos(buf, n);
  g_mtime = mtime;
  pthread_mutex_unlock(&g_lock);
  free(buf);
  return 0;
}

int airos_lookup_by_ip(const char *ip, airos_station_t *out) {
  if (!ip || !out) return -1;
  pthread_mutex_lock(&g_lock);
  for (size_t i = 0; i < g_entries_n; ++i) {
    if (g_entries[i].ip[0] && strcmp(g_entries[i].ip, ip) == 0) {
      if (g_entries[i].info.valid) *out = g_entries[i].info; else out->valid = 0;
      pthread_mutex_unlock(&g_lock); return 0;
    }
  }
  pthread_mutex_unlock(&g_lock);
  return -1;
}

int airos_lookup_by_mac(const char *mac, airos_station_t *out) {
  if (!mac || !out) return -1;
  pthread_mutex_lock(&g_lock);
  for (size_t i = 0; i < g_entries_n; ++i) {
    if (g_entries[i].mac[0] && strcmp(g_entries[i].mac, mac) == 0) {
      if (g_entries[i].info.valid) *out = g_entries[i].info; else out->valid = 0;
      pthread_mutex_unlock(&g_lock); return 0;
    }
  }
  pthread_mutex_unlock(&g_lock);
  return -1;
}
