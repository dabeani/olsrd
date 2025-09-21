
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "util.h"

static void strtoupper(char *s){ for(;*s;++s) *s=toupper((unsigned char)*s); }

struct arp_row { char ip[64], mac[64], dev[64]; };

static int list_bridges(char out[][64], int max){
  int c = 0;
  DIR *d = opendir("/sys/class/net");
  if (!d) return 0;
  struct dirent *de;
  while ((de = readdir(d)) && c < max) {
    if (strncmp(de->d_name, "br", 2) == 0) {
  size_t need = strlen("/sys/class/net/") + strlen(de->d_name) + strlen("/bridge") + 1;
  char *p = (char*)malloc(need);
      if (!p) continue;
      snprintf(p, need, "/sys/class/net/%s/bridge", de->d_name);
      struct stat st;
      if (stat(p, &st) == 0) {
  snprintf(out[c], sizeof(out[0]), "%.63s", de->d_name);
        c++;
      }
      free(p);
    }
  }
  closedir(d);
  return c;
}

static int bridge_ports(const char *br, char out[][64], int max){
  int c = 0;
  size_t need = strlen("/sys/class/net/") + strlen(br) + strlen("/brif") + 1;
  char *dir = (char*)malloc(need);
  if (!dir) return 0;
  snprintf(dir, need, "/sys/class/net/%s/brif", br);
  DIR *d = opendir(dir);
  if (!d) { free(dir); return 0; }
  struct dirent *de;
  while ((de = readdir(d)) && c < max) {
  if (de->d_name[0] == '.') continue;
  snprintf(out[c], sizeof(out[0]), "%.63s", de->d_name);
    c++;
  }
  closedir(d);
  free(dir);
  return c;
}

static int load_arp(struct arp_row *rows, int max){
  FILE *f=fopen("/proc/net/arp","r"); if(!f) return 0;
  char line[512]; int c=0; if(!fgets(line,sizeof(line),f)){ fclose(f); return 0; } // header
  while(fgets(line,sizeof(line),f) && c<max){
    char ip[64], mac[64], dev[64];
    if (sscanf(line,"%63s %*s %*s %63s %*s %63s", ip, mac, dev)==3){
  snprintf(rows[c].ip, sizeof(rows[c].ip), "%s", ip);
  snprintf(rows[c].mac, sizeof(rows[c].mac), "%s", mac);
  strtoupper(rows[c].mac);
  snprintf(rows[c].dev, sizeof(rows[c].dev), "%s", dev);
  c++;
    }
  } fclose(f); return c;
}

/* Read permanent MAC from sysfs: /sys/class/net/<if>/address */
static int read_sysfs_mac(const char *ifname, char *out, size_t outlen) {
  if (!ifname || !out) return 0;
  char path[256]; snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifname);
  FILE *f = fopen(path, "r"); if (!f) return 0;
  char buf[128]; if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 0; }
  fclose(f);
  /* trim newline */
  char *nl = strchr(buf, '\n'); if (nl) *nl = '\0';
  /* uppercase */
  for (char *p = buf; *p; ++p) *p = toupper((unsigned char)*p);
  snprintf(out, outlen, "%s", buf);
  return 1;
}

/* Collect IPv4 addresses assigned to interface via getifaddrs */
static int collect_ifaddrs_ipv4(const char *ifname, char ips[][64], int max) {
  if (!ifname || !ips) return 0;
  struct ifaddrs *ifap, *ifa; int count = 0;
  if (getifaddrs(&ifap) != 0) return 0;
  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr) continue;
    if (ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, ifname) == 0) {
  char buf[INET_ADDRSTRLEN]; struct sockaddr_in sin_tmp;
  /* copy into properly aligned local storage to avoid unaligned access on some platforms */
  memcpy(&sin_tmp, ifa->ifa_addr, sizeof(sin_tmp));
  if (inet_ntop(AF_INET, &sin_tmp.sin_addr, buf, sizeof(buf))) {
        /* dedupe */
        int dup = 0; for (int k=0;k<count;k++) if (strcmp(buf, ips[k])==0) dup = 1;
        if (!dup && count < max) { snprintf(ips[count], sizeof(ips[0]), "%s", buf); count++; }
      }
    }
  }
  freeifaddrs(ifap);
  return count;
}

int render_connections_plain(char **buf_out, size_t *len_out) __attribute__((visibility("default")));
__attribute__((used, visibility("default")))
int render_connections_plain(char **buf_out, size_t *len_out){
  char *buf = NULL; size_t cap = 8192; size_t len = 0;
  buf = (char*)malloc(cap);
  if (!buf) return -1;
  #define APPEND(fmt,...) do{ \
    char t[1024]; \
    int _app_n = snprintf(t, sizeof(t), fmt, ##__VA_ARGS__); \
    /* snprintf returns the number of characters that would have been written; cap copy to buffer size-1 */ \
    if (_app_n >= (int)sizeof(t)) _app_n = (int)sizeof(t) - 1; \
    if (_app_n > 0) { \
      if (len + (size_t)_app_n + 1 > cap) { \
        while (cap < len + (size_t)_app_n + 1) cap *= 2; \
        char *nb2 = (char*)realloc(buf, cap); \
        if (!nb2) { free(buf); return -1; } \
        buf = nb2; \
      } \
      memcpy(buf + len, t, (size_t)_app_n); \
      len += (size_t)_app_n; \
      buf[len] = 0; \
    } \
  } while(0)

  char bridges[32][64]; int nb = list_bridges(bridges, 32);
  fprintf(stderr, "[render_connections] listed %d bridges\n", nb);
  struct arp_row *arps = NULL; int na = 0;
  /* allocate arp rows on heap to avoid large stack usage */
  arps = (struct arp_row*)malloc(sizeof(*arps) * 1024);
  if (arps) {
    na = load_arp(arps, 1024);
  } else {
    /* fallback: try to load into a small stack array if malloc fails */
    struct arp_row tmp_arps[64]; na = load_arp(tmp_arps, 64);
    if (na > 0) {
      /* copy to heap for consistent free semantics */
      arps = (struct arp_row*)malloc(sizeof(*arps) * na);
      if (arps) memcpy(arps, tmp_arps, sizeof(*arps) * na);
    }
  }
  fprintf(stderr, "[render_connections] loaded %d arp rows (arps=%p)\n", na, (void*)arps);

  APPEND("# connections (plugin)\n");
  if (nb>0){
  for (int i = 0; i < nb; i++) {
      /* allocate ports array on heap to avoid large stack frames */
      char (*ports)[64] = (char(*)[64])malloc(sizeof(char[64][64]));
      int np = 0;
      if (ports) {
        np = bridge_ports(bridges[i], ports, 64);
    fprintf(stderr, "[render_connections] bridge %s has %d ports\n", bridges[i], np);
        for (int p = 0; p < np; p++) {
          for (int a = 0; a < na; a++) {
            if (arps && strcmp(arps[a].dev, ports[p]) == 0) {
              APPEND(" . %s\t%s\t%s\n", bridges[i], ports[p], arps[a].mac);
            }
          }
        }
        for (int a = 0; a < na; a++) {
          for (int p = 0; p < np; p++) {
            if (arps && strcmp(arps[a].dev, ports[p]) == 0) {
              APPEND(" ~ %s\t%s\t%s\n", ports[p], arps[a].mac, arps[a].ip);
            }
          }
        }
      }
      APPEND("_\n");
      if (ports) free(ports);
    }
  } else {
    for (int a = 0; a < na; a++) {
      if (arps) APPEND(" ~ %s\t%s\t%s\n", arps[a].dev, arps[a].mac, arps[a].ip);
    }
  }

  *buf_out = buf; *len_out = len;
  if (arps) free(arps);
  return 0;
}

/* Render connections as JSON for consumption by the web UI */
int render_connections_json(char **buf_out, size_t *len_out) __attribute__((visibility("default")));
int render_connections_json(char **buf_out, size_t *len_out){
  char *buf = NULL; size_t cap = 8192; size_t len = 0;
  buf = (char*)malloc(cap);
  if (!buf) return -1;
  #define JAPPEND(fmt,...) do{ \
    char t[1024]; \
    int _app_n = snprintf(t, sizeof(t), fmt, ##__VA_ARGS__); \
    if (_app_n >= (int)sizeof(t)) _app_n = (int)sizeof(t) - 1; \
    if (_app_n > 0) { \
      if (len + (size_t)_app_n + 1 > cap) { \
        while (cap < len + (size_t)_app_n + 1) cap *= 2; \
        char *nb2 = (char*)realloc(buf, cap); \
        if (!nb2) { free(buf); return -1; } \
        buf = nb2; \
      } \
      memcpy(buf + len, t, (size_t)_app_n); \
      len += (size_t)_app_n; \
      buf[len] = 0; \
    } \
  } while(0)

  JAPPEND("{\"ports\":[");
  char bridges[32][64]; int nb = list_bridges(bridges, 32);
  struct arp_row *arps = NULL; int na = 0;
  arps = (struct arp_row*)malloc(sizeof(*arps) * 1024);
  if (arps) na = load_arp(arps, 1024);

  int first_port = 1;
  if (nb>0){
    for (int i = 0; i < nb; i++) {
      char (*ports)[64] = (char(*)[64])malloc(sizeof(char[64][64]));
      int np = 0;
      if (ports) {
        np = bridge_ports(bridges[i], ports, 64);
        for (int p = 0; p < np; p++) {
          /* collect macs and ips for this port */
          int mac_count = 0; int ip_count = 0;
          char macs[64][64]; char ips[64][64];
          for (int a = 0; a < na; a++) {
            if (arps && strcmp(arps[a].dev, ports[p]) == 0) {
              /* add mac */
              int dup = 0; for (int k=0;k<mac_count;k++) if (strcmp(macs[k], arps[a].mac)==0) dup=1;
              if (!dup) { snprintf(macs[mac_count], sizeof(macs[0]), "%s", arps[a].mac); mac_count++; }
              /* add ip */
              int dup2 = 0; for (int k=0;k<ip_count;k++) if (strcmp(ips[k], arps[a].ip)==0) dup2=1;
              if (!dup2) { snprintf(ips[ip_count], sizeof(ips[0]), "%s", arps[a].ip); ip_count++; }
            }
          }
          /* Fallbacks when ARP had no entries for this port: read sysfs MAC and getifaddrs IPs */
          if (mac_count == 0) {
            char macbuf[64] = "";
            if (read_sysfs_mac(ports[p], macbuf, sizeof(macbuf))) {
              snprintf(macs[mac_count], sizeof(macs[0]), "%s", macbuf); mac_count++;
            }
          }
          if (ip_count == 0) {
            char ipbufs[64][64]; int got = collect_ifaddrs_ipv4(ports[p], ipbufs, 64);
            for (int ii=0; ii<got && ip_count < 64; ii++) { snprintf(ips[ip_count], sizeof(ips[0]), "%s", ipbufs[ii]); ip_count++; }
          }
          if (!first_port) JAPPEND(",");
          JAPPEND("{\"port\":\"%s\",\"bridge\":\"%s\",\"macs\":[", ports[p], bridges[i]);
          for (int m=0;m<mac_count;m++){ if (m) JAPPEND(","); JAPPEND("\"%s\"", macs[m]); }
          JAPPEND("] ,\"ips\":[");
          for (int m=0;m<ip_count;m++){ if (m) JAPPEND(","); JAPPEND("\"%s\"", ips[m]); }
          JAPPEND("] ,\"notes\":\"\"}");
          first_port = 0;
        }
      }
      if (ports) free(ports);
    }
  } else {
    /* no bridges: iterate arp rows and expose ports as device entries */
    for (int a = 0; a < na; a++) {
      if (!first_port) JAPPEND(",");
      /* If ARP present use it, otherwise try sysfs/getifaddrs fallback */
      char macs_f[64][64]; char ips_f[64][64]; int mc=0, ic=0;
      if (arps && arps[a].mac[0]) { snprintf(macs_f[mc++], sizeof(macs_f[0]), "%s", arps[a].mac); }
      if (arps && arps[a].ip[0]) { snprintf(ips_f[ic++], sizeof(ips_f[0]), "%s", arps[a].ip); }
      if (mc==0) { char macbuf[64]; if (read_sysfs_mac(arps[a].dev, macbuf, sizeof(macbuf))) { snprintf(macs_f[mc++], sizeof(macs_f[0]), "%s", macbuf); } }
      if (ic==0) { int got = collect_ifaddrs_ipv4(arps[a].dev, ips_f, 64); ic += got; }
      JAPPEND("{\"port\":\"%s\",\"bridge\":\"\",\"macs\":[", arps[a].dev);
      for (int m=0;m<mc;m++){ if (m) JAPPEND(","); JAPPEND("\"%s\"", macs_f[m]); }
      JAPPEND("],\"ips\":[");
      for (int m=0;m<ic;m++){ if (m) JAPPEND(","); JAPPEND("\"%s\"", ips_f[m]); }
      JAPPEND("],\"notes\":\"\"}");
      first_port = 0;
    }
  }

  JAPPEND("]}\n");
  *buf_out = buf; *len_out = len;
  if (arps) free(arps);
  return 0;
}

