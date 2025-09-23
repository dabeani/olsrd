#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <unistd.h>
#include <sys/socket.h>


int util_exec(const char *cmd, char **out, size_t *outlen) {
  /* Cap total output to avoid unbounded memory consumption from spawns */
  const size_t MAX_EXEC_OUTPUT = 1024 * 1024; /* 1 MiB */
  *out = NULL; *outlen = 0;
  if (!cmd) return -1;
  FILE *fp = popen(cmd, "r");
  if (!fp) return -1;
  size_t cap = 8192;
  if (cap > MAX_EXEC_OUTPUT) cap = MAX_EXEC_OUTPUT;
  char *buf = (char*)malloc(cap);
  if (!buf) { pclose(fp); return -1; }
  size_t len = 0;
  size_t n;
  while (!feof(fp)) {
    size_t want = 4096;
    if (MAX_EXEC_OUTPUT - len == 0) {
      /* reached maximum allowed output; stop reading further */
      break;
    }
    if (want > MAX_EXEC_OUTPUT - len) want = MAX_EXEC_OUTPUT - len;
    if (cap - len < want) {
      size_t newcap = cap * 2;
      if (newcap > MAX_EXEC_OUTPUT) newcap = MAX_EXEC_OUTPUT;
      if (newcap <= cap) {
        /* cannot grow further */
        break;
      }
      char *nb = (char*)realloc(buf, newcap);
      if (!nb) { free(buf); pclose(fp); return -1; }
      buf = nb; cap = newcap;
    }
    n = fread(buf + len, 1, want, fp);
    if (n == 0) break;
    len += n;
  }
  pclose(fp);
  /* null-terminate the returned buffer for safety */
  if (len >= MAX_EXEC_OUTPUT) {
    /* ensure last byte reserved for NUL */
    len = MAX_EXEC_OUTPUT - 1;
  }
  char *nb = (char*)realloc(buf, len + 1);
  if (nb) buf = nb;
  buf[len] = '\0';
  *out = buf;
  *outlen = len;
  return 0;
}

int util_read_file(const char *path, char **out, size_t *outlen) {
  *out = NULL; *outlen = 0;
  FILE *f = fopen(path, "rb");
  if (!f) return -1;
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (sz < 0) { fclose(f); return -1; }
  /* Prevent trying to read extremely large files into memory (cap at 5 MiB) */
  const long MAX_FILE_READ = 5 * 1024 * 1024;
  if (sz > MAX_FILE_READ) { fclose(f); return -1; }
  /* allocate one extra byte for a terminating NUL to make the buffer string-safe */
  char *buf = (char*)malloc((size_t)sz + 1);
  if (!buf) { fclose(f); return -1; }
  if (sz > 0) {
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); fclose(f); return -1; }
  }
  buf[(size_t)sz] = '\0';
  fclose(f);
  *out = buf;
  *outlen = (size_t)sz;
  return 0;
}

int util_file_exists(const char *path) {
  struct stat st;
  return stat(path, &st) == 0;
}

/* Simple local HTTP GET helper for localhost endpoints. Parses URLs of form
 * http://127.0.0.1:PORT/path and returns the response body (headers removed).
 * This avoids spawning curl for local requests.
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>

int util_http_get_url_local(const char *url, char **out, size_t *outlen, int timeout_sec) {
  if (!url || !out || !outlen) return -1;
  *out = NULL; *outlen = 0;
  /* Quick parsing: expect prefix http://127.0.0.1[:port]/path */
  const char *p = url;
  if (strncmp(p, "http://", 7) == 0) p += 7; else return -1;
  if (strncmp(p, "127.0.0.1", 9) != 0 && strncmp(p, "localhost", 9) != 0) return -1;
  /* find port if present */
  int port = 80; const char *q = p + 9; if (*q == ':') { q++; port = atoi(q); while(*q && *q != '/') q++; } else { while(*q && *q != '/') q++; }
  const char *path = (*q) ? q : "/";

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  struct sockaddr_in sa; memset(&sa,0,sizeof(sa)); sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port); sa.sin_addr.s_addr = inet_addr("127.0.0.1");
  /* set non-blocking connect with timeout */
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  int res = connect(fd, (struct sockaddr*)&sa, sizeof(sa));
  if (res < 0) {
    if (errno != EINPROGRESS) { close(fd); return -1; }
    fd_set wf; FD_ZERO(&wf); FD_SET(fd, &wf);
    struct timeval tv; tv.tv_sec = timeout_sec; tv.tv_usec = 0;
    res = select(fd+1, NULL, &wf, NULL, &tv);
    if (res <= 0) { close(fd); return -1; }
    int err = 0; socklen_t el = sizeof(err); if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0) { close(fd); return -1; }
    if (err) { close(fd); return -1; }
  }
  /* set blocking and timeouts for recv */
  if (flags >= 0) fcntl(fd, F_SETFL, flags);
  struct timeval to; to.tv_sec = timeout_sec; to.tv_usec = 0; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));

  char req[1024]; int rn = snprintf(req, sizeof(req), "GET %s HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", path);
  if (rn < 0 || rn >= (int)sizeof(req)) { close(fd); return -1; }
  if (send(fd, req, (size_t)rn, 0) != rn) { close(fd); return -1; }

  const size_t MAX_BODY = 512 * 1024; /* 512 KiB */
  size_t cap = 8192; if (cap > MAX_BODY) cap = MAX_BODY; char *buf = malloc(cap); if(!buf){ close(fd); return -1; }
  size_t len = 0; ssize_t n;
  while ((n = recv(fd, buf + len, (ssize_t)(cap - len), 0)) > 0) {
    len += (size_t)n;
    if (len >= MAX_BODY) {
      /* reached cap, stop reading further */
      break;
    }
    if (cap - len < 4096) {
      size_t newcap = cap * 2; if (newcap > MAX_BODY) newcap = MAX_BODY;
      char *nb = realloc(buf, newcap); if (!nb) { free(buf); close(fd); return -1; } buf = nb; cap = newcap;
    }
  }
  close(fd);
  if (len == 0) { free(buf); return -1; }
  /* find end of headers */
  char *body = NULL; for (size_t i = 0; i + 3 < len; ++i) { if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') { body = buf + i + 4; size_t body_len = len - (i + 4);
        char *outb = malloc(body_len + 1); if (!outb) { free(buf); return -1; } memcpy(outb, body, body_len); outb[body_len] = '\0'; *out = outb; *outlen = body_len; free(buf); return 0; } }
  /* fallback: return whole buffer as body */
  char *outb = malloc(len + 1); if (!outb) { free(buf); return -1; } memcpy(outb, buf, len); outb[len] = '\0'; *out = outb; *outlen = len; free(buf); return 0;
}

/* Generic HTTP GET helper for non-TLS URLs. This reuses the local loopback
 * implementation but accepts arbitrary hostnames/IPs (no TLS). It is a
 * lightweight replacement for spawning curl for plain http:// URLs.
 */
int util_http_get_url(const char *url, char **out, size_t *outlen, int timeout_sec) {
  if (!url || !out || !outlen) return -1;
  *out = NULL; *outlen = 0;
  const char *p = url;
  if (strncmp(p, "http://", 7) == 0) p += 7; else return -1;
  /* Extract host[:port] and path */
  char host[256]; char path[512]; int port = 80;
  const char *slash = strchr(p, '/');
  size_t hostlen = slash ? (size_t)(slash - p) : strlen(p);
  if (hostlen == 0 || hostlen >= sizeof(host)) return -1;
  memcpy(host, p, hostlen);
  host[hostlen] = '\0';
  if (slash) {
    size_t pathlen = strlen(slash);
    size_t copy = pathlen < (sizeof(path)-1) ? pathlen : (sizeof(path)-1);
    memcpy(path, slash, copy);
    path[copy] = '\0';
  } else strcpy(path, "/");
  /* parse optional :port */
  char *colon = strchr(host, ':'); if (colon) { *colon = '\0'; port = atoi(colon+1); if (port<=0) port=80; }

  struct addrinfo hints; struct addrinfo *res = NULL; char sport[16]; int rv;
  memset(&hints,0,sizeof(hints)); hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
  snprintf(sport, sizeof(sport), "%d", port);
  if ((rv = getaddrinfo(host, sport, &hints, &res)) != 0) return -1;
  int sock = -1; struct addrinfo *ai;
  for (ai = res; ai != NULL; ai = ai->ai_next) {
    sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock < 0) continue;
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags >= 0) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
      if (errno != EINPROGRESS) { close(sock); sock = -1; continue; }
      fd_set wf; FD_ZERO(&wf); FD_SET(sock, &wf);
      struct timeval tv; tv.tv_sec = timeout_sec; tv.tv_usec = 0;
      int sret = select(sock+1, NULL, &wf, NULL, &tv);
      if (sret <= 0) { close(sock); sock = -1; continue; }
      int err = 0; socklen_t el = sizeof(err); if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &el) < 0) { close(sock); sock = -1; continue; }
      if (err) { close(sock); sock = -1; continue; }
    }
    /* connected */
    if (flags >= 0) fcntl(sock, F_SETFL, flags);
    struct timeval to; to.tv_sec = timeout_sec; to.tv_usec = 0; setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));
    break;
  }
  freeaddrinfo(res);
  if (sock < 0) return -1;

  char req[1024]; int rn = snprintf(req, sizeof(req), "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\nUser-Agent: status-plugin\r\nAccept: application/json\r\n\r\n", path, host);
  if (rn < 0 || rn >= (int)sizeof(req)) { close(sock); return -1; }
  if (send(sock, req, (size_t)rn, 0) != rn) { close(sock); return -1; }

  const size_t MAX_BODY = 1024 * 1024; /* 1 MiB */
  size_t cap = 8192; char *buf = malloc(cap); if(!buf){ close(sock); return -1; }
  size_t len = 0; ssize_t n;
  while ((n = recv(sock, buf + len, (ssize_t)(cap - len), 0)) > 0) {
    len += (size_t)n;
    if (len >= MAX_BODY) break;
    if (cap - len < 4096) {
      size_t newcap = cap * 2; if (newcap > MAX_BODY) newcap = MAX_BODY;
      char *nb = realloc(buf, newcap); if (!nb) { free(buf); close(sock); return -1; } buf = nb; cap = newcap;
    }
  }
  close(sock);
  if (len == 0) { free(buf); return -1; }
  /* strip headers */
  char *body = NULL; for (size_t i = 0; i + 3 < len; ++i) { if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') { body = buf + i + 4; size_t body_len = len - (i + 4);
        char *outb = malloc(body_len + 1); if (!outb) { free(buf); return -1; } memcpy(outb, body, body_len); outb[body_len] = '\0'; *out = outb; *outlen = body_len; free(buf); return 0; } }
  char *outb = malloc(len + 1); if (!outb) { free(buf); return -1; } memcpy(outb, buf, len); outb[len] = '\0'; *out = outb; *outlen = len; free(buf); return 0;
}

int util_is_container(void) {
  if (util_file_exists("/.dockerenv")) return 1;
  char *c=NULL; size_t n=0;
  if (util_read_file("/proc/1/cgroup", &c, &n)==0 && c) {
    if (memmem(c, n, "docker", 6) || memmem(c, n, "kubepods", 8)) { free(c); return 1; }
    free(c);
  }
  return 0;
}


#include <sys/stat.h>
int path_exists(const char *p){ struct stat st; return stat(p,&st)==0; }
int env_is_edgerouter(void){
  if (path_exists("/etc/edgeos-release")) return 1;
  if (path_exists("/etc/version") && path_exists("/etc/ubnt")) return 1;
  if (path_exists("/tmp/10-all.json")) return 1;
  return 0;
}

int env_is_linux_container(void){
  /* Detect Linux container environment (not EdgeRouter) */
  if (env_is_edgerouter()) return 0; /* If it's EdgeRouter, it's not a container */

  /* Check for container indicators */
  if (path_exists("/.dockerenv")) return 1;
  if (path_exists("/run/.containerenv")) return 1; /* podman */

  /* Check for common container paths */
  if (path_exists("/etc/alpine-release")) return 1;
  if (path_exists("/etc/os-release")) {
    /* Check if it's Alpine or other container-friendly distro */
    FILE *f = fopen("/etc/os-release", "r");
    if (f) {
      char line[256];
      while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "Alpine") || strstr(line, "BusyBox")) {
          fclose(f);
          return 1;
        }
      }
      fclose(f);
    }
  }

  /* Check for typical container networking */
  if (path_exists("/proc/net/route")) {
    /* If we have very few interfaces, might be containerized */
    FILE *f = fopen("/proc/net/route", "r");
    if (f) {
      int lines = 0;
      char line[256];
      while (fgets(line, sizeof(line), f)) lines++;
      fclose(f);
      if (lines <= 3) return 1; /* Very few routes, likely container */
    }
  }

  return 0;
}

/* Allocate a buffer with initial capacity and initialize len=0, buf[0]=0 */
char *util_buffer_alloc(size_t initial_cap) {
  char *buf = malloc(initial_cap);
  if (!buf) return NULL;
  buf[0] = '\0';
  return buf;
}

/* Reset a buffer: free existing, allocate new with initial_cap, set len=0 */
char *util_buffer_reset(char **buf, size_t *len, size_t *cap, size_t initial_cap) {
  if (*buf) free(*buf);
  *buf = NULL;
  *cap = initial_cap;
  *len = 0;
  *buf = malloc(initial_cap);
  if (!*buf) return NULL;
  (*buf)[0] = '\0';
  return *buf;
}
