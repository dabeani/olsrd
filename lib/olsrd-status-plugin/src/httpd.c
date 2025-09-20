#include "httpd.h"
#include <pthread.h>
#include <sys/stat.h>
#include <stdlib.h>
int path_exists(const char *p);
extern int g_is_edgerouter;
/* allow optional request debug toggle (defined in plugin) */
extern int g_log_request_debug;
#include <sys/types.h>
#include <sys/socket.h>
#if defined(__linux__)
#include <sys/sendfile.h>
#endif
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include <netinet/tcp.h>

typedef struct http_handler_node {
  char route[64];
  http_handler_fn fn;
  struct http_handler_node *next;
} http_handler_node_t;

static int g_srv_fd = -1;
static pthread_t g_srv_th;
static int g_run = 0;
static char g_asset_root[512] = {0};
static http_handler_node_t *g_handlers = NULL;
static pthread_mutex_t g_handlers_lock = PTHREAD_MUTEX_INITIALIZER;
/* control whether per-request access logging is enabled (env OLSRD_STATUS_ACCESS_LOG=0 disables) */
static int g_log_access = 1;
/* simple allow-list storage */
typedef struct cidr_entry {
  struct in6_addr addr;
  int prefix; /* 0-128 */
  struct cidr_entry *next;
} cidr_entry_t;
static cidr_entry_t *g_allowed = NULL;

/* forward declare conn_arg_t for pool usage; full struct defined later */
typedef struct conn_arg conn_arg_t;

/* --- connection/request object pools and optional thread-pool --- */


static int parse_cidr(const char *s, struct in6_addr *out_addr, int *out_prefix) {
  if (!s || !out_addr || !out_prefix) return -1;
  char tmp[128]; snprintf(tmp, sizeof(tmp), "%s", s);
  char *sp = strchr(tmp, ' ');
  char *slash = strchr(tmp, '/');
  if (sp) {
    /* format: "addr mask" */
    *sp = 0; char *addr = tmp; char *mask = sp+1; /* mask like 255.255.252.0 */
    struct in_addr a, m;
    if (inet_pton(AF_INET, addr, &a) == 1 && inet_pton(AF_INET, mask, &m) == 1) {
      /* convert to in6 mapped */
      memset(out_addr, 0, sizeof(*out_addr));
      out_addr->s6_addr[10] = 0xff; out_addr->s6_addr[11] = 0xff;
      memcpy(&out_addr->s6_addr[12], &a, 4);
      uint32_t maskbe; memcpy(&maskbe, &m, 4);
      maskbe = ntohl(maskbe);
      int p = 0; for (int i=31;i>=0;--i) if (maskbe & (1u<<i)) p++; else break;
  /* IPv4 occupies the low 32 bits of the IPv6 mapped address; convert to IPv6 prefix space */
  *out_prefix = p + 96;
      return 0;
    }
    return -1;
  } else if (slash) {
    /* cidr like 193.238.156.0/22 or IPv6*/
    if (strchr(tmp, ':')) {
      /* IPv6 */
      char *cp = strchr(tmp,'/'); if (!cp) return -1; *cp=0; char *pfx = cp+1;
      if (inet_pton(AF_INET6, tmp, out_addr) != 1) return -1;
      *out_prefix = atoi(pfx);
      return 0;
    } else {
      char *cp = strchr(tmp,'/'); *cp=0; char *pfx = cp+1; struct in_addr a;
      if (inet_pton(AF_INET, tmp, &a) != 1) return -1;
      memset(out_addr,0,sizeof(*out_addr)); out_addr->s6_addr[10]=0xff; out_addr->s6_addr[11]=0xff; memcpy(&out_addr->s6_addr[12], &a,4);
  /* IPv4 CIDR prefix is relative to the 32-bit IPv4 portion; convert to IPv6 prefix */
  *out_prefix = atoi(pfx) + 96;
      return 0;
    }
  } else {
    /* single address */
    struct in_addr a;
    if (inet_pton(AF_INET, tmp, &a) == 1) {
      memset(out_addr,0,sizeof(*out_addr)); out_addr->s6_addr[10]=0xff; out_addr->s6_addr[11]=0xff; memcpy(&out_addr->s6_addr[12], &a,4);
  /* single IPv4 address -> full 32-bit match inside IPv6 mapped space */
  *out_prefix = 32 + 96; return 0;
    }
    if (inet_pton(AF_INET6, tmp, out_addr) == 1) { *out_prefix = 128; return 0; }
    return -1;
  }
}

int http_allow_cidr(const char *cidr_or_addr_mask) {
  struct in6_addr a; int p;
  if (parse_cidr(cidr_or_addr_mask, &a, &p) != 0) return -1;
  int was_empty = (g_allowed == NULL);
  cidr_entry_t *e = calloc(1, sizeof(*e)); if (!e) return -1;
  e->addr = a; e->prefix = p; e->next = g_allowed; g_allowed = e;
  if (was_empty) {
  if (g_log_access) fprintf(stderr, "[httpd] access restricted: Net parameter(s) found, only allowed networks will have access\n");
  }
  /* Optional debug: print each added entry in readable form when requested */
  const char *dbg = getenv("OLSR_DEBUG_ALLOWLIST");
  if (dbg && dbg[0]=='1') {
    char buf[128];
    /* show IPv4-mapped addresses as IPv4/prefix when appropriate */
    if (e->addr.s6_addr[10] == 0xff && e->addr.s6_addr[11] == 0xff) {
      char v4[64]; snprintf(v4, sizeof(v4), "%u.%u.%u.%u", (unsigned char)e->addr.s6_addr[12], (unsigned char)e->addr.s6_addr[13], (unsigned char)e->addr.s6_addr[14], (unsigned char)e->addr.s6_addr[15]);
      snprintf(buf, sizeof(buf), "%s/%d", v4, e->prefix - 96);
    } else {
      if (inet_ntop(AF_INET6, &e->addr, buf, sizeof(buf)) == NULL) snprintf(buf, sizeof(buf), "<inet_ntop_fail>");
    }
    fprintf(stderr, "[httpd][debug] added allow-list entry: %s (prefix=%d)\n", buf, e->prefix);
  }
  return 0;
}

static int addr_prefix_match(const struct in6_addr *a, const struct in6_addr *b, int prefix) {
  if (prefix <= 0) return 1;
  int full_bytes = prefix / 8;
  int rem_bits = prefix % 8;
  if (full_bytes > 16) full_bytes = 16;
  if (memcmp(a, b, full_bytes) != 0) return 0;
  if (rem_bits == 0) return 1;
  unsigned char mask = (unsigned char)(0xff << (8 - rem_bits));
  return ( (a->s6_addr[full_bytes] & mask) == (b->s6_addr[full_bytes] & mask) );
}

int http_is_client_allowed(const char *client_ip) {
  if (!client_ip) return 0;
  if (!g_allowed) return 1; /* no restrictions */
  struct in6_addr a; if (strchr(client_ip,':')) {
    if (inet_pton(AF_INET6, client_ip, &a) != 1) return 0;
  } else {
    struct in_addr v4; if (inet_pton(AF_INET, client_ip, &v4) != 1) return 0;
    memset(&a,0,sizeof(a)); a.s6_addr[10]=0xff; a.s6_addr[11]=0xff; memcpy(&a.s6_addr[12], &v4,4);
  }
  const char *dbg = getenv("OLSR_DEBUG_ALLOWLIST");
  int debug = (dbg && dbg[0]=='1') ? 1 : 0;
  if (debug) {
    char cip[64]; snprintf(cip, sizeof(cip), "%s", client_ip);
  if (g_log_access) fprintf(stderr, "[httpd][debug] checking client IP %s against %s allow-list entries\n", cip, g_allowed?"current":"none");
  }
  for (cidr_entry_t *e = g_allowed; e; e = e->next) {
    if (debug) {
      char buf[128];
      if (e->addr.s6_addr[10] == 0xff && e->addr.s6_addr[11] == 0xff) {
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u/%d", (unsigned char)e->addr.s6_addr[12], (unsigned char)e->addr.s6_addr[13], (unsigned char)e->addr.s6_addr[14], (unsigned char)e->addr.s6_addr[15], e->prefix-96);
      } else {
        if (inet_ntop(AF_INET6, &e->addr, buf, sizeof(buf)) == NULL) snprintf(buf, sizeof(buf), "<inet_ntop_fail>");
      }
  if (g_log_access) fprintf(stderr, "[httpd][debug] testing entry %s (prefix=%d)\n", buf, e->prefix);
    }
    if (addr_prefix_match(&a, &e->addr, e->prefix)) return 1;
  }
  return 0;
}

void http_clear_allowlist(void) {
  cidr_entry_t *e = g_allowed;
  while (e) { cidr_entry_t *nx = e->next; free(e); e = nx; }
  g_allowed = NULL;
}

void http_log_allowlist(void) {
  if (!g_allowed) { if (g_log_access) fprintf(stderr, "[httpd] allow-list is empty (no restrictions)\n"); return; }
  if (g_log_access) fprintf(stderr, "[httpd] configured allow-list entries:\n");
  for (cidr_entry_t *e = g_allowed; e; e = e->next) {
    char buf[128];
    if (e->addr.s6_addr[10] == 0xff && e->addr.s6_addr[11] == 0xff) {
      snprintf(buf, sizeof(buf), "%u.%u.%u.%u/%d", (unsigned char)e->addr.s6_addr[12], (unsigned char)e->addr.s6_addr[13], (unsigned char)e->addr.s6_addr[14], (unsigned char)e->addr.s6_addr[15], e->prefix-96);
    } else {
      if (inet_ntop(AF_INET6, &e->addr, buf, sizeof(buf)) == NULL) snprintf(buf, sizeof(buf), "<inet_ntop_fail>");
    }
  if (g_log_access) fprintf(stderr, "  - %s (prefix=%d)\n", buf, e->prefix);
  }
}

static int starts_with(const char *s, const char *p) {
  size_t ls = strlen(s), lp = strlen(p);
  return (ls >= lp && strncmp(s, p, lp) == 0) ? 1 : 0;
}

int http_server_register_handler(const char *route, http_handler_fn fn) {
  http_handler_node_t *n = (http_handler_node_t*)calloc(1, sizeof(*n));
  if (!n) {
    fprintf(stderr, "[httpd] ERROR: failed to allocate handler node for route '%s'\n", route);
    fflush(stderr);
    return -1;
  }
  snprintf(n->route, sizeof(n->route), "%s", route);
  n->fn = fn;
  pthread_mutex_lock(&g_handlers_lock);
  n->next = g_handlers;
  g_handlers = n;
  pthread_mutex_unlock(&g_handlers_lock);
  fprintf(stderr, "[httpd] DEBUG: registered handler for route '%s' at %p (fn=%p)\n", route, (void*)n, (void*)fn);
  fflush(stderr);
  return 0;
}

void http_send_status(http_request_t *r, int code, const char *status) {
  /* Buffer the status line and common headers to reduce syscalls. Caller will flush via http_printf/http_write. */
  int n = snprintf(r->hdr_buf, sizeof(r->hdr_buf),
                   "HTTP/1.1 %d %s\r\n"
                   "Connection: close\r\n"
                   "Server: olsrd-status-plugin\r\n",
                   code, status ? status : "");
  if (n > 0 && (size_t)n < sizeof(r->hdr_buf)) {
    r->hdr_len = (size_t)n;
    r->hdr_pending = 1;
  } else {
    /* fallback: immediate write on formatting failure */
    ssize_t _rv = write(r->fd, r->hdr_buf, (n>0 && n<=(int)sizeof(r->hdr_buf))?n:0); (void)_rv;
    r->hdr_len = 0; r->hdr_pending = 0;
  }
}

void http_write(http_request_t *r, const char *buf, size_t len) {
  if (r->hdr_pending) {
    /* Use writev to send headers + body, but loop to handle partial writes. */
    struct iovec iov[2];
    iov[0].iov_base = r->hdr_buf; iov[0].iov_len = r->hdr_len;
    iov[1].iov_base = (void*)buf; iov[1].iov_len = len;
    size_t total_to_write = iov[0].iov_len + iov[1].iov_len;
    size_t total_written = 0;
    while (total_written < total_to_write) {
      /* Attempt to write remaining data. */
      ssize_t rv = writev(r->fd, iov, 2);
      if (rv < 0) {
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) { /* temporary, try again briefly */
          usleep(1000);
          continue;
        }
        /* unrecoverable error: stop trying */
        break;
      }
      /* advance by rv bytes: adjust iov buffers accordingly */
      total_written += (size_t)rv;
      if ((size_t)rv >= iov[0].iov_len) {
        /* consumed at least all of header part */
        size_t hdr_consumed = iov[0].iov_len;
        size_t body_consumed = (size_t)rv - hdr_consumed;
        /* zero out header iov so next writev focuses on body only */
        iov[0].iov_base = NULL; iov[0].iov_len = 0;
        if (body_consumed >= iov[1].iov_len) {
          /* done */
          iov[1].iov_base = NULL; iov[1].iov_len = 0;
        } else {
          /* advance body pointer */
          iov[1].iov_base = (void*)((char*)iov[1].iov_base + body_consumed);
          iov[1].iov_len -= body_consumed;
        }
      } else {
        /* only part of header consumed */
        size_t hdr_consumed = (size_t)rv;
        iov[0].iov_base = (void*)((char*)iov[0].iov_base + hdr_consumed);
        iov[0].iov_len -= hdr_consumed;
        /* body unchanged */
      }
    }
    r->hdr_pending = 0; r->hdr_len = 0;
  } else {
    /* Plain write loop to ensure all bytes are written */
    size_t off = 0;
    while (off < len) {
      ssize_t rv = write(r->fd, buf + off, len - off);
      if (rv < 0) {
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) { usleep(1000); continue; }
        break;
      }
      off += (size_t)rv;
    }
  }
}

int http_printf(http_request_t *r, const char *fmt, ...) {
  char b[8192];
  va_list ap;
  va_start(ap, fmt);
  /* fmt can be non-literal but we intentionally forward it; suppress the
   * -Wformat-nonliteral warning locally to keep the build clean.
   */
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
  int n = vsnprintf(b, sizeof(b), fmt, ap);
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
  va_end(ap);
  if (n > 0) {
    if (r->hdr_pending) {
      /* Use writev and loop to handle partial writes reliably */
      struct iovec iov[2];
      iov[0].iov_base = r->hdr_buf; iov[0].iov_len = r->hdr_len;
      iov[1].iov_base = b; iov[1].iov_len = (size_t)n;
      size_t total_to_write = iov[0].iov_len + iov[1].iov_len;
      size_t total_written = 0;
      while (total_written < total_to_write) {
        ssize_t rv = writev(r->fd, iov, 2);
        if (rv < 0) {
          if (errno == EINTR) continue;
          if (errno == EAGAIN || errno == EWOULDBLOCK) { usleep(1000); continue; }
          break;
        }
        total_written += (size_t)rv;
        if ((size_t)rv >= iov[0].iov_len) {
          /* consumed header part */
          size_t hdr_consumed = iov[0].iov_len;
          size_t body_consumed = (size_t)rv - hdr_consumed;
          iov[0].iov_base = NULL; iov[0].iov_len = 0;
          if (body_consumed >= iov[1].iov_len) {
            iov[1].iov_base = NULL; iov[1].iov_len = 0;
          } else {
            iov[1].iov_base = (void*)((char*)iov[1].iov_base + body_consumed);
            iov[1].iov_len -= body_consumed;
          }
        } else {
          /* only part of header consumed */
          size_t hdr_consumed = (size_t)rv;
          iov[0].iov_base = (void*)((char*)iov[0].iov_base + hdr_consumed);
          iov[0].iov_len -= hdr_consumed;
        }
      }
      r->hdr_pending = 0; r->hdr_len = 0;
    } else {
      /* Loop on write to ensure full buffer is sent */
      size_t off = 0;
      while (off < (size_t)n) {
        ssize_t rv = write(r->fd, b + off, (size_t)n - off);
        if (rv < 0) {
          if (errno == EINTR) continue;
          if (errno == EAGAIN || errno == EWOULDBLOCK) { usleep(1000); continue; }
          break;
        }
        off += (size_t)rv;
      }
    }
  }
  return n;
}

static const char *guess_mime(const char *p) {
  const char *ext = strrchr(p, '.');
  if (!ext) return "application/octet-stream";
  ext++;
  if (!strcmp(ext,"css")) return "text/css";
  if (!strcmp(ext,"js")) return "application/javascript";
  if (!strcmp(ext,"png")) return "image/png";
  if (!strcmp(ext,"ico")) return "image/x-icon";
  if (!strcmp(ext,"map")) return "application/json";
  if (!strcmp(ext,"woff")) return "font/woff";
  if (!strcmp(ext,"woff2")) return "font/woff2";
  if (!strcmp(ext,"ttf")) return "font/ttf";
  if (!strcmp(ext,"eot")) return "application/vnd.ms-fontobject";
  if (!strcmp(ext,"svg")) return "image/svg+xml";
  if (!strcmp(ext,"html")) return "text/html; charset=utf-8";
  return "application/octet-stream";
}

int http_send_file(http_request_t *r, const char *asset_root, const char *relpath, const char *mime) {
  char path[1024];
  snprintf(path, sizeof(path), "%s/%s", asset_root, relpath);
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
  fprintf(stderr, "[status-plugin] http_send_file: open('%s') failed: %s (errno=%d)\n", path, strerror(errno), errno);
  http_send_status(r, 404, "Not Found");
  http_printf(r, "Content-Type: text/plain\r\n\r\nnot found\n");
  return -1;
  }
  const char *m = mime ? mime : guess_mime(relpath);
  if (g_log_access) fprintf(stderr, "[status-plugin] http_send_file: serving '%s' (mime=%s)\n", path, m);
  struct stat st;
  if (fstat(fd, &st) == 0) {
    /* Generate Last-Modified header */
    char lm[128];
    struct tm *gmt = gmtime(&st.st_mtime);
    if (gmt) strftime(lm, sizeof(lm), "%a, %d %b %Y %H:%M:%S GMT", gmt); else lm[0]=0;
    /* Cache static assets for 1 day by default */
    http_send_status(r, 200, "OK");
    if (lm[0]) {
      http_printf(r, "Content-Type: %s\r\nCache-Control: public, max-age=86400\r\nLast-Modified: %s\r\n\r\n", m, lm);
    } else {
      http_printf(r, "Content-Type: %s\r\nCache-Control: public, max-age=86400\r\n\r\n", m);
    }
  } else {
    http_send_status(r, 200, "OK");
    http_printf(r, "Content-Type: %s\r\n\r\n", m);
  }
  /* Try to use efficient zero-copy sendfile when available */
#if defined(__linux__)
  off_t offset = 0;
  while (offset < st.st_size) {
    ssize_t s = sendfile(r->fd, fd, &offset, st.st_size - offset);
    if (s < 0) {
      if (errno == EINTR) continue;
      /* fallback to userspace copy */
      break;
    }
    if (s == 0) break;
  }
  if (offset >= st.st_size) { close(fd); return 0; }
#endif
  char buf[16384];
  ssize_t n;
  while ((n = read(fd, buf, sizeof(buf))) > 0) {
    ssize_t _wret = write(r->fd, buf, (size_t)n); (void)_wret;
  }
  close(fd);
  return 0;
}

static void urldecode(char *s) {
  char *o = s;
  while (*s) {
    if (*s == '%' && isxdigit((unsigned char)s[1]) && isxdigit((unsigned char)s[2])) {
      char hx[3] = { s[1], s[2], 0 };
      *o++ = (char)strtol(hx, NULL, 16);
      s += 3;
    } else if (*s == '+') {
      *o++ = ' ';
      s++;
    } else {
      *o++ = *s++;
    }
  }
  *o = 0;
}

/* per-connection worker: wraps the existing inline handling into a thread */
typedef struct conn_arg {
  int cfd;
  struct sockaddr_storage ss;
  struct conn_arg *next;
} conn_arg_t;

/* forward prototypes for functions implemented below */
static void conn_arg_free(conn_arg_t *ca);
static http_request_t *http_request_alloc(void);
static void http_request_free(http_request_t *r);
static void *connection_worker(void *arg);

/* exported accessor for runtime httpd stats (conn pool + task queue) */
void httpd_get_runtime_stats(int *conn_pool_len, int *task_count, int *pool_enabled, int *pool_size);

static void *connection_worker(void *arg) {
  conn_arg_t *ca = (conn_arg_t*)arg;
  int cfd = ca->cfd;
  struct sockaddr_storage ss = ca->ss;
  /* return conn_arg to pool early so its memory can be reused immediately */
  conn_arg_free(ca);
  /* Harden per-connection socket: set a short recv timeout so slow clients can't hang the worker */
  struct timeval tv;
  tv.tv_sec = 5; tv.tv_usec = 0;
  setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  /* also set a small send timeout so slow receivers don't stall workers indefinitely */
  struct timeval stv;
  stv.tv_sec = 5; stv.tv_usec = 0;
  setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &stv, sizeof(stv));
  /* Disable Nagle to reduce latency for small responses */
  int _one = 1; setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &_one, sizeof(_one));
  char buf[8192];
  ssize_t n = read(cfd, buf, sizeof(buf)-1);
  if (n <= 0) { close(cfd); return NULL; }
  if ((size_t)n >= sizeof(buf)-1) { close(cfd); return NULL; }
  buf[n] = 0;
  http_request_t *r = http_request_alloc(); if (!r) { close(cfd); return NULL; }
  r->fd = cfd;
  snprintf(r->client_ip, sizeof(r->client_ip), "unknown");
  if (ss.ss_family == AF_INET) {
    struct sockaddr_in *in = (struct sockaddr_in*)&ss;
    if (inet_ntop(AF_INET, &in->sin_addr, r->client_ip, sizeof(r->client_ip)) == NULL) {
      snprintf(r->client_ip, sizeof(r->client_ip), "unknown");
      if (g_log_access) fprintf(stderr, "[httpd][warn] inet_ntop(AF_INET) failed: %s\n", strerror(errno));
    }
  } else if (ss.ss_family == AF_INET6) {
    struct sockaddr_in6 *in6 = (struct sockaddr_in6*)&ss;
    if (inet_ntop(AF_INET6, &in6->sin6_addr, r->client_ip, sizeof(r->client_ip)) == NULL) {
      snprintf(r->client_ip, sizeof(r->client_ip), "unknown");
      if (g_log_access) fprintf(stderr, "[httpd][warn] inet_ntop(AF_INET6) failed: %s\n", strerror(errno));
    }
  }
  /* If for any reason we couldn't determine the client IP, leave as 'unknown' */
  char *sp1 = strchr(buf, ' ');
  if (!sp1) { close(cfd); http_request_free(r); return NULL; }
  *sp1 = 0;
  snprintf(r->method, sizeof(r->method), "%.7s", buf);
  if (!(strcmp(r->method, "GET") == 0 || strcmp(r->method, "HEAD") == 0)) {
    http_send_status(r, 405, "Method Not Allowed");
    http_printf(r, "Content-Type: text/plain\r\n\r\nMethod not allowed\n");
    close(cfd); http_request_free(r); return NULL;
  }
  char *sp2 = strchr(sp1+1, ' ');
  if (!sp2) { close(cfd); http_request_free(r); return NULL; }
  *sp2 = 0;
  char *path = sp1+1;
  char *q = strchr(path, '?'); if (q) { *q = 0; size_t qlen = strnlen(q+1, sizeof(r->query)-1); if (qlen >= sizeof(r->query)-1) qlen = sizeof(r->query)-1; memcpy(r->query, q+1, qlen); r->query[qlen]=0; urldecode(r->query); }
  size_t plen = strnlen(path, sizeof(r->path)-1); if (plen >= sizeof(r->path)-1) plen = sizeof(r->path)-1; memcpy(r->path, path, plen); r->path[plen]=0;
  char *hosth = strcasestr(sp2+1, "\nHost:"); if (hosth) { hosth += 6; while (*hosth==' ' || *hosth=='\t') hosth++; char *e = strpbrk(hosth, "\r\n"); if (e) *e = 0; size_t hlen = strnlen(hosth, sizeof(r->host)-1); if (hlen >= sizeof(r->host)-1) hlen = sizeof(r->host)-1; memcpy(r->host, hosth, hlen); r->host[hlen]=0; }
  /* Request line: only emit when per-request debug is enabled */
  if (g_log_request_debug) fprintf(stderr, "[httpd] request: %s %s from %s query='%s' host='%s'\n", r->method, r->path, r->client_ip, r->query, r->host);
  /* Optional per-endpoint request debug logging (disabled by default). When enabled,
   * emit an abbreviated line for GET /status/stats requests to help diagnosing UI fetches.
   */
  if (g_log_request_debug && strcmp(r->method, "GET") == 0 && strcmp(r->path, "/status/stats") == 0) {
    fprintf(stderr, "[httpd][debug] request: %s %s from %s\n", r->method, r->path, r->client_ip);
  }

  /* DEBUG: Add immediate debug print after request logging */
  fprintf(stderr, "[httpd] DEBUG: REQUEST PROCESSED - path='%s' method='%s'\n", r->path, r->method);
  fflush(stderr);

  /* Enforce allow-list even for static assets */
  fprintf(stderr, "[httpd] DEBUG: checking client allow-list for %s\n", r->client_ip);
  fflush(stderr);
  if (!http_is_client_allowed(r->client_ip)) { if (g_log_access) fprintf(stderr, "[httpd] client %s not allowed to access %s\n", r->client_ip, r->path); struct linger _lg = {1, 0}; setsockopt(cfd, SOL_SOCKET, SO_LINGER, &_lg, sizeof(_lg)); close(cfd); http_request_free(r); return NULL; }
  fprintf(stderr, "[httpd] DEBUG: client allowed, checking static assets\n");
  fflush(stderr);
  if (starts_with(r->path, "/css/") || starts_with(r->path, "/js/") || starts_with(r->path, "/fonts/")) { if (g_log_access) fprintf(stderr, "[httpd] static asset request: %s (serve from %s)\n", r->path, g_asset_root); http_send_file(r, g_asset_root, r->path+1, NULL); close(cfd); http_request_free(r); return NULL; }
  fprintf(stderr, "[httpd] DEBUG: not static asset, dispatching to handlers\n");
  fflush(stderr);
  /* dispatch to registered handlers */
  pthread_mutex_lock(&g_handlers_lock);
  http_handler_node_t *nptr = g_handlers;
  int handler_count = 0;
  while (nptr) {
    handler_count++;
    nptr = nptr->next;
  }
  fprintf(stderr, "[httpd] DEBUG: dispatching to %d handlers\n", handler_count);
  fflush(stderr);
  /* Snapshot handler pointers while holding the lock to avoid races with registration/unregistration
   * which may free nodes concurrently. We copy pointers into a small array and then iterate without the
   * lock, preventing dereferencing freed memory inside the lock window. The list length is precomputed above.
   */
  int handled = 0;
  fprintf(stderr, "[httpd] DEBUG: starting handler dispatch loop, g_handlers=%p (count=%d)\n", (void*)g_handlers, handler_count);
  fflush(stderr);
  /* Create a safe snapshot by copying route and fn into a local buffer while holding the lock. This
   * prevents dereferencing handler nodes after they may have been freed by other threads. */
  struct handler_entry { char route[64]; http_handler_fn fn; } *snapshot = NULL;
  if (handler_count > 0) {
    snapshot = calloc((size_t)handler_count, sizeof(*snapshot));
    if (snapshot) {
      int idx = 0; http_handler_node_t *it = g_handlers;
      while (it && idx < handler_count) {
        /* copy route and function pointer */
  /* Use snprintf to avoid -Wstringop-truncation warnings and ensure termination */
  snprintf(snapshot[idx].route, sizeof(snapshot[idx].route), "%s", it->route);
        snapshot[idx].fn = it->fn;
        idx++; it = it->next;
      }
      handler_count = idx;
    } else {
      fprintf(stderr, "[httpd] DEBUG: snapshot allocation failed, will iterate under lock\n"); fflush(stderr);
    }
  }
  /* release lock before calling handlers if we have a safe snapshot */
  if (snapshot) pthread_mutex_unlock(&g_handlers_lock);
  if (snapshot) {
    for (int i = 0; i < handler_count; ++i) {
      struct handler_entry *ent = &snapshot[i];
      fprintf(stderr, "[httpd] DEBUG: checking handler %d: idx=%d route='%s' fn=%p\n",
              i+1, i, ent->route, (void*)ent->fn);
      fflush(stderr);
      if (ent->route[0] && strcmp(ent->route, r->path) == 0) {
        fprintf(stderr, "[httpd] DEBUG: found matching handler for '%s' (idx=%d), calling it\n", r->path, i);
        fflush(stderr);
        handled = 1;
        if (!http_is_client_allowed(r->client_ip)) {
          if (g_log_access) fprintf(stderr, "[httpd] client %s not allowed to access %s\n", r->client_ip, ent->route);
          struct linger _lg2 = {1,0}; setsockopt(cfd, SOL_SOCKET, SO_LINGER, &_lg2, sizeof(_lg2)); close(cfd); http_request_free(r); free(snapshot); return NULL;
        }
        fprintf(stderr, "[httpd] DEBUG: calling handler function %p for route '%s'\n", (void*)ent->fn, ent->route);
        fflush(stderr);
        ent->fn(r);
        fprintf(stderr, "[httpd] DEBUG: handler returned\n"); fflush(stderr);
        break;
      }
    }
    free(snapshot);
  } else {
    /* snapshot failed -> iterate with lock held (existing behavior) */
    handler_count = 0;
    nptr = g_handlers;
    while (nptr) {
      handler_count++;
      fprintf(stderr, "[httpd] DEBUG: checking handler %d: node=%p next=%p route='%s' fn=%p\n",
              handler_count, (void*)nptr, (void*)nptr->next, nptr->route, (void*)nptr->fn);
      fflush(stderr);
      if (nptr->route[0] && strcmp(nptr->route, r->path) == 0) {
        fprintf(stderr, "[httpd] DEBUG: found matching handler for '%s', calling it\n", r->path);
        fflush(stderr);
        handled = 1;
        pthread_mutex_unlock(&g_handlers_lock);
        if (!http_is_client_allowed(r->client_ip)) {
          if (g_log_access) fprintf(stderr, "[httpd] client %s not allowed to access %s\n", r->client_ip, nptr->route);
          struct linger _lg2 = {1,0}; setsockopt(cfd, SOL_SOCKET, SO_LINGER, &_lg2, sizeof(_lg2)); close(cfd); http_request_free(r); return NULL;
        }
        fprintf(stderr, "[httpd] DEBUG: calling handler function %p for route '%s'\n", (void*)nptr->fn, nptr->route);
        fflush(stderr);
        nptr->fn(r);
        fprintf(stderr, "[httpd] DEBUG: handler returned\n"); fflush(stderr);
        break;
      }
      if (!nptr->next) {
        fprintf(stderr, "[httpd] DEBUG: reached end of handler list (nptr->next is NULL)\n"); fflush(stderr);
        break;
      }
      nptr = nptr->next;
    }
    if (!handled) pthread_mutex_unlock(&g_handlers_lock);
  }
  if (!handled) {
    pthread_mutex_unlock(&g_handlers_lock);
  }
  fprintf(stderr, "[httpd] DEBUG: handler dispatch completed, checked %d handlers, handled=%d\n", handler_count, handled);
  fflush(stderr);
  if (!handled) {
    if (g_log_access) fprintf(stderr, "[httpd] 404 Not Found: %s\n", r->path);
    http_send_status(r, 404, "Not Found");
    http_printf(r, "Content-Type: text/plain\r\n\r\nnot found: %s\n", r->path);
  }
  close(cfd);
  http_request_free(r);
  return NULL;
}

/* --- connection/request object pools and optional thread-pool --- */
static pthread_mutex_t g_conn_pool_lock = PTHREAD_MUTEX_INITIALIZER;
static conn_arg_t *g_conn_pool = NULL; /* freelist head */
static int g_conn_pool_len = 0;
static int g_conn_pool_max = 128;

typedef struct http_req_pool_node { struct http_req_pool_node *next; http_request_t *r; } http_req_pool_node_t;
static pthread_mutex_t g_req_pool_lock = PTHREAD_MUTEX_INITIALIZER;
static http_req_pool_node_t *g_req_pool = NULL;
static int g_req_pool_len = 0;
static int g_req_pool_max = 128;

/* task queue for thread-pool */
static pthread_mutex_t g_task_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_task_cond = PTHREAD_COND_INITIALIZER;
static struct task_node { conn_arg_t *ca; struct task_node *next; } *g_task_head = NULL, *g_task_tail = NULL;
static int g_task_count = 0;

static pthread_t *g_pool_workers = NULL;
static int g_pool_size = 0;
static int g_pool_enabled = 0; /* enabled if env OLSRD_STATUS_THREAD_POOL=1 */

/* Allocate/free conn_arg_t with small freelist fallback to malloc */
static conn_arg_t *conn_arg_alloc(void) {
  conn_arg_t *ca = NULL;
  pthread_mutex_lock(&g_conn_pool_lock);
  if (g_conn_pool) {
    ca = g_conn_pool; g_conn_pool = g_conn_pool->next; g_conn_pool_len--; pthread_mutex_unlock(&g_conn_pool_lock); memset(ca,0,sizeof(*ca)); return ca;
  }
  pthread_mutex_unlock(&g_conn_pool_lock);
  ca = calloc(1, sizeof(*ca));
  return ca;
}

static void conn_arg_free(conn_arg_t *ca) {
  if (!ca) return;
  pthread_mutex_lock(&g_conn_pool_lock);
  if (g_conn_pool_len < g_conn_pool_max) {
    ca->next = g_conn_pool; g_conn_pool = ca; g_conn_pool_len++; pthread_mutex_unlock(&g_conn_pool_lock); return;
  }
  pthread_mutex_unlock(&g_conn_pool_lock);
  free(ca);
}

void httpd_get_runtime_stats(int *conn_pool_len, int *task_count, int *pool_enabled, int *pool_size) {
  int cp = 0, tc = 0, pe = 0, ps = 0;
  pthread_mutex_lock(&g_conn_pool_lock);
  cp = g_conn_pool_len;
  pthread_mutex_unlock(&g_conn_pool_lock);
  pthread_mutex_lock(&g_task_lock);
  tc = g_task_count;
  pe = g_pool_enabled;
  ps = g_pool_size;
  pthread_mutex_unlock(&g_task_lock);
  if (conn_pool_len) *conn_pool_len = cp;
  if (task_count) *task_count = tc;
  if (pool_enabled) *pool_enabled = pe;
  if (pool_size) *pool_size = ps;
}

/* http_request pool - node-sized pool; http_request_t may be larger but we reuse memory */
static http_request_t *http_request_alloc(void) {
  http_req_pool_node_t *node = NULL;
  pthread_mutex_lock(&g_req_pool_lock);
  if (g_req_pool) {
    node = g_req_pool; g_req_pool = g_req_pool->next; g_req_pool_len--; pthread_mutex_unlock(&g_req_pool_lock);
    http_request_t *r = node->r; node->r = NULL; free(node); memset(r, 0, sizeof(*r)); return r;
  }
  pthread_mutex_unlock(&g_req_pool_lock);
  http_request_t *r = calloc(1, sizeof(*r)); return r;
}

static void http_request_free(http_request_t *r) {
  if (!r) return;
  pthread_mutex_lock(&g_req_pool_lock);
  if (g_req_pool_len < g_req_pool_max) {
    http_req_pool_node_t *node = calloc(1, sizeof(*node));
    if (node) {
      node->r = r;
      node->next = g_req_pool;
      g_req_pool = node;
      g_req_pool_len++;
      pthread_mutex_unlock(&g_req_pool_lock);
      return;
    }
  }
  pthread_mutex_unlock(&g_req_pool_lock);
  free(r);
}

/* task queue push/pop */
static void task_queue_push(conn_arg_t *ca) {
  struct task_node *t = malloc(sizeof(*t)); if (!t) { /* fallback: spawn thread directly */
    pthread_t th; int rc = pthread_create(&th, NULL, connection_worker, (void*)ca); if (rc==0) pthread_detach(th); else { conn_arg_free(ca); close(ca->cfd); }
    return;
  }
  t->ca = ca; t->next = NULL;
  pthread_mutex_lock(&g_task_lock);
  if (!g_task_tail) { g_task_head = g_task_tail = t; } else { g_task_tail->next = t; g_task_tail = t; }
  g_task_count++;
  pthread_cond_signal(&g_task_cond);
  pthread_mutex_unlock(&g_task_lock);
}

static conn_arg_t *task_queue_pop(void) {
  pthread_mutex_lock(&g_task_lock);
  while (g_run && !g_task_head) pthread_cond_wait(&g_task_cond, &g_task_lock);
  if (!g_run && !g_task_head) { pthread_mutex_unlock(&g_task_lock); return NULL; }
  struct task_node *t = g_task_head; g_task_head = t->next; if (!g_task_head) g_task_tail = NULL; g_task_count--;
  pthread_mutex_unlock(&g_task_lock);
  conn_arg_t *ca = t->ca; free(t); return ca;
}

/* pool worker thread */
static void *pool_worker(void *arg) {
  (void)arg;
  while (g_run) {
    conn_arg_t *ca = task_queue_pop();
    if (!ca) break;
    /* handle connection inline */
    connection_worker((void*)ca);
    /* connection_worker frees ca internally? ensure freeing here if not */
    /* connection_worker frees the conn_arg at start; double-free avoided because we changed semantics below */
  }
  return NULL;
}

static void *server_thread(void *arg) {
  (void)arg;
  fprintf(stderr, "[httpd] DEBUG: server_thread started, g_handlers=%p\n", (void*)g_handlers);
  fflush(stderr);
  while (g_run) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    int cfd = accept(g_srv_fd, (struct sockaddr *)&ss, &sl);
    if (cfd < 0) {
      if (errno == EINTR) continue;
      if (!g_run) break;
      continue;
    }
    /* Dispatch accepted socket using pooled conn_arg and either push to task queue or spawn a detached thread */
    conn_arg_t *ca = conn_arg_alloc();
    if (!ca) { close(cfd); continue; }
    ca->cfd = cfd;
    /* copy only up to sl bytes (clamped) to avoid overruns; zero the rest */
    size_t copy_len = (sl <= sizeof(ca->ss)) ? (size_t)sl : sizeof(ca->ss);
    memset(&ca->ss, 0, sizeof(ca->ss));
    memcpy(&ca->ss, &ss, copy_len);
    if (g_pool_enabled && g_pool_size > 0) {
      task_queue_push(ca);
    } else {
            pthread_t th; int rc = pthread_create(&th, NULL, connection_worker, (void*)ca);
            if (rc == 0) pthread_detach(th); else { /* fallback: free and close socket on failure */ conn_arg_free(ca); close(cfd); }
    }
  }
  return NULL;
}

int http_server_start(const char *bind_ip, int port, const char *asset_root) {
  fprintf(stderr, "[httpd] DEBUG: http_server_start called with bind_ip='%s', port=%d, asset_root='%s', current g_handlers=%p\n", 
          bind_ip ? bind_ip : "NULL", port, asset_root ? asset_root : "NULL", (void*)g_handlers);
  fflush(stderr);
  if (asset_root) snprintf(g_asset_root, sizeof(g_asset_root), "%s", asset_root);
  /* Respect new env var OLSRD_STATUS_FETCH_LOG_QUEUE to silence fetch/request access logs
   * If not present, fall back to the older OLSRD_STATUS_ACCESS_LOG for compatibility.
   * Values: '0' disables access logging; any other value (or unset) enables it.
   */
  const char *fl = getenv("OLSRD_STATUS_FETCH_LOG_QUEUE");
  if (fl && fl[0] == '0') {
    g_log_access = 0;
  } else {
    const char *alog = getenv("OLSRD_STATUS_ACCESS_LOG");
    if (alog && alog[0] == '0') g_log_access = 0; else g_log_access = 1;
  }
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons((uint16_t)port);
  a.sin_addr.s_addr = inet_addr(bind_ip ? bind_ip : "0.0.0.0");
  if (bind(fd, (struct sockaddr*)&a, sizeof(a)) < 0) { close(fd); return -1; }
  if (listen(fd, 64) < 0) { close(fd); return -1; }
  g_srv_fd = fd;
  g_run = 1;
  /* thread-pool opt-in via env OLSRD_STATUS_THREAD_POOL=1, size via OLSRD_STATUS_THREAD_POOL_SIZE */
  const char *tp = getenv("OLSRD_STATUS_THREAD_POOL");
  if (tp && tp[0] == '1') {
    g_pool_enabled = 1;
    const char *ts = getenv("OLSRD_STATUS_THREAD_POOL_SIZE");
    int psz = 4;
    if (ts) { char *endptr = NULL; long v = strtol(ts, &endptr, 10); if (endptr && *endptr == '\0' && v > 0 && v <= 128) psz = (int)v; }
    g_pool_size = psz;
    g_pool_workers = calloc(g_pool_size, sizeof(pthread_t));
    for (int i = 0; i < g_pool_size; ++i) {
      if (pthread_create(&g_pool_workers[i], NULL, pool_worker, NULL) != 0) {
        /* on failure, reduce pool size */ g_pool_size = i; break;
      }
    }
  }
  if (pthread_create(&g_srv_th, NULL, server_thread, NULL) != 0) {
    close(fd); g_srv_fd = -1; g_run = 0; return -1;
  }
  return 0;
}

void http_server_stop(void) {
  fprintf(stderr, "[httpd] DEBUG: http_server_stop called, g_handlers=%p\n", (void*)g_handlers);
  fflush(stderr);
  if (!g_run) return;
  g_run = 0;
  if (g_srv_fd >= 0) { shutdown(g_srv_fd, SHUT_RDWR); close(g_srv_fd); g_srv_fd = -1; }
  /* wake up the server thread and pool workers */
  pthread_cond_broadcast(&g_task_cond);
  pthread_join(g_srv_th, NULL);
  if (g_pool_enabled && g_pool_workers) {
    /* wake workers and join them */
    pthread_cond_broadcast(&g_task_cond);
    for (int i = 0; i < g_pool_size; ++i) pthread_join(g_pool_workers[i], NULL);
    free(g_pool_workers); g_pool_workers = NULL; g_pool_size = 0; g_pool_enabled = 0;
  }
  pthread_mutex_lock(&g_handlers_lock);
  http_handler_node_t *n = g_handlers;
  while (n) { http_handler_node_t *nx = n->next; free(n); n = nx; }
  g_handlers = NULL;
  pthread_mutex_unlock(&g_handlers_lock);
  fprintf(stderr, "[httpd] DEBUG: http_server_stop completed, handlers cleaned up\n");
  fflush(stderr);
}


/* --- built-in connections (forward decl from connections.c) --- */
int render_connections_plain(char **buf_out, size_t *len_out);
static void h_connections_builtin(http_request_t *r) __attribute__((unused));
static void h_connections_builtin(http_request_t *r){
  char *buf=NULL; size_t len=0;
  if (render_connections_plain(&buf,&len)==0 && buf && len>0){
    http_send_status(r, 200, "OK");
    http_write(r, buf, len);
    free(buf);
  } else {
    http_send_status(r, 204, "No Content");
  }
}

/* --- capabilities JSON --- */
static void h_capabilities(http_request_t *r) __attribute__((unused));
static void h_capabilities(http_request_t *r){
  http_send_status(r, 200, "OK");
  http_printf(r,
    "{\"is_edgerouter\":%s,"
     "\"discover\":%s,"
     "\"airos\":%s,"
     "\"connections\":true,"
     "\"traffic\":%s,"
     "\"txtinfo\":true,"
     "\"jsoninfo\":true}",
    g_is_edgerouter ? "true":"false",
    g_is_edgerouter ? "true":"false",
    g_is_edgerouter ? "true":"false",
    path_exists("/tmp") ? "true":"false"

  );
}

/* Serve index.html at "/" from assetroot; fallback to text summary */
static void h_root_fallback(http_request_t *r) __attribute__((unused));
static void h_root_fallback(http_request_t *r) {
  http_send_status(r, 200, "OK");
  http_printf(r, "olsrd-status-plugin\n(no index.html found at assetroot: %s)\n", g_asset_root);
}

/* Serve index.html at "/" using the existing asset server */
static void h_root(http_request_t *r) __attribute__((unused));
static void h_root(http_request_t *r){
  if (http_send_file(r, g_asset_root, "index.html", "text/html; charset=utf-8") != 0){
    /* Fallback to embedded minimal HTML */
    http_send_status(r, 200, "OK");
    http_printf(r, "Content-Type: text/html; charset=utf-8\r\n\r\n");
    http_printf(r, "<!DOCTYPE html><html><head><title>OLSR Status</title></head><body>\n");
    http_printf(r, "<h1>OLSR Status Plugin</h1>\n");
    http_printf(r, "<p>Asset files not found at: %s</p>\n", g_asset_root);
    http_printf(r, "<p>Check plugin installation and assetroot parameter.</p>\n");
    http_printf(r, "<p><a href='/status'>Status JSON</a> | <a href='/capabilities'>Capabilities</a></p>\n");
    http_printf(r, "</body></html>\n");
  }
}
