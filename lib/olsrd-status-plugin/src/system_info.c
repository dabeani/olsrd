/* System information collection utilities for olsrd-status-plugin */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <time.h>

#include "util.h"
#include "system_info.h"
#include <ifaddrs.h>
#include <net/if.h>
#if defined(__linux__)
#include <sys/sysinfo.h>
#endif

/* Get system hostname */
void get_system_hostname(char *hostname, size_t len) {
  if (gethostname(hostname, len) == 0) {
    hostname[len - 1] = '\0';
  } else {
    hostname[0] = '\0';
  }
}

/* Get primary IPv4 address (first non-loopback) */
void get_primary_ipv4(char *ipaddr, size_t len) {
  ipaddr[0] = '\0';
  struct ifaddrs *ifap = NULL, *ifa = NULL;

  if (getifaddrs(&ifap) == 0) {
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
      if (!ifa->ifa_addr) continue;
      if (ifa->ifa_addr->sa_family == AF_INET) {
        char bufip[INET_ADDRSTRLEN] = "";
        struct sockaddr_in sa_local;
        memset(&sa_local, 0, sizeof(sa_local));
        memcpy(&sa_local, ifa->ifa_addr, sizeof(sa_local));
        inet_ntop(AF_INET, &sa_local.sin_addr, bufip, sizeof(bufip));
        if (strcmp(bufip, "127.0.0.1") != 0) {
          snprintf(ipaddr, len, "%s", bufip);
          break;
        }
      }
    }
    freeifaddrs(ifap);
  }
}

/* Get system uptime in seconds */
long get_system_uptime_seconds(void) {
  long uptime = -1;

#if defined(__linux__)
  struct sysinfo si;
  if (sysinfo(&si) == 0) {
    uptime = si.uptime;
  } else {
    /* Fallback: parse /proc/uptime */
    FILE *f = fopen("/proc/uptime", "r");
    if (f) {
      double up;
      if (fscanf(f, "%lf", &up) == 1) {
        uptime = (long)up;
      }
      fclose(f);
    }
  }
#endif

  /* Fallback: parse /proc/stat for btime */
  if (uptime < 0) {
    char *statc = NULL;
    size_t sn = 0;
    if (util_read_file("/proc/stat", &statc, &sn) == 0 && statc) {
      char *line = statc;
      char *end = statc + sn;
      while (line < end) {
        char *nl = memchr(line, '\n', (size_t)(end - line));
        size_t ll = nl ? (size_t)(nl - line) : (size_t)(end - line);
        if (ll > 6 && memcmp(line, "btime ", 6) == 0) {
          long btime = atol(line + 6);
          if (btime > 0) {
            time_t now = time(NULL);
            if (now > btime) {
              uptime = now - btime;
            }
          }
          break;
        }
        if (!nl) break;
        line = nl + 1;
      }
      free(statc);
    }
  }

  return uptime < 0 ? 0 : uptime;
}

/* Get default IPv4 route information */
void get_default_ipv4_route(char *ip, size_t ip_len, char *dev, size_t dev_len) {
  ip[0] = '\0';
  dev[0] = '\0';

  char *rout = NULL;
  size_t rn = 0;
  if (util_exec("/sbin/ip -4 route show default 2>/dev/null || /usr/sbin/ip -4 route show default 2>/dev/null || ip -4 route show default 2>/dev/null", &rout, &rn) == 0 && rout) {
    char *p = strstr(rout, "via ");
    if (p) {
      p += 4;
      char *q = strchr(p, ' ');
      if (q) {
        size_t L = q - p;
        if (L < ip_len) {
          strncpy(ip, p, L);
          ip[L] = '\0';
        }
      }
    }
    p = strstr(rout, " dev ");
    if (p) {
      p += 5;
      char *q = strchr(p, ' ');
      if (!q) q = strchr(p, '\n');
      if (q) {
        size_t L = q - p;
        if (L < dev_len) {
          strncpy(dev, p, L);
          dev[L] = '\0';
        }
      }
    }
    free(rout);
  }
}

/* Get default IPv6 route information */
void get_default_ipv6_route(char *ip, size_t ip_len, char *dev, size_t dev_len) {
  ip[0] = '\0';
  dev[0] = '\0';

  char *r6 = NULL;
  size_t r6n = 0;
  if (util_exec("/sbin/ip -6 route show default 2>/dev/null || /usr/sbin/ip -6 route show default 2>/dev/null || ip -6 route show default 2>/dev/null", &r6, &r6n) == 0 && r6) {
    char *p = strstr(r6, "via ");
    if (p) {
      p += 4;
      char *q = strchr(p, ' ');
      if (q) {
        size_t L = q - p;
        if (L < ip_len) {
          strncpy(ip, p, L);
          ip[L] = '\0';
        }
      }
    }
    p = strstr(r6, " dev ");
    if (p) {
      p += 5;
      char *q = strchr(p, ' ');
      if (!q) q = strchr(p, '\n');
      if (q) {
        size_t L = q - p;
        if (L < dev_len) {
          strncpy(dev, p, L);
          dev[L] = '\0';
        }
      }
    }
    free(r6);
  }
}