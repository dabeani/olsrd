#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdarg.h>

/* forward declaration to satisfy -Wmissing-prototypes when this file is
 * compiled as a separate translation unit. The function is used from
 * other files and declared there as well. */
int normalize_olsrd_links_plain(const char *raw, char **outbuf, size_t *outlen);
int normalize_olsrd_neighbors_plain(const char *raw, char **outbuf, size_t *outlen);
int normalize_olsrd_routes_plain(const char *raw, char **outbuf, size_t *outlen);
int normalize_olsrd_topology_plain(const char *raw, char **outbuf, size_t *outlen);

/* use shared JSON helpers */
#include "json_helpers.h"

/* extern declaration for hostname lookup */
extern void lookup_hostname_cached(const char *ip, char *out, size_t outlen);

/* strip simple HTML tags: keep inner text of <...>text</...> or cut at '<' */
static void strip_tags_and_trim(char *s) {
  if (!s || !s[0]) return;
  char *pstart = strchr(s, '>');
  if (pstart) {
    pstart++;
    char *pend = strchr(pstart, '<');
    if (pend) *pend = '\0';
    memmove(s, pstart, strlen(pstart) + 1);
  } else {
    char *lt = strchr(s, '<'); if (lt) *lt = '\0';
  }
  /* left trim */
  while (*s && isspace((unsigned char)*s)) memmove(s, s+1, strlen(s));
  /* right trim */
  char *t = s + strlen(s) - 1; while (t >= s && isspace((unsigned char)*t)) { *t = '\0'; t--; }
}

int normalize_olsrd_links_plain(const char *raw, char **outbuf, size_t *outlen) {
  if (!raw || !outbuf || !outlen) return -1;
  *outbuf = NULL; *outlen = 0;
  const char *tbl = strstr(raw, "Table: Links");
  if (!tbl) return -1;
  const char *p = tbl;
  while (*p && *p != '\n') p++;
  if (*p == '\n') p++;
  const char *hdr_start = p;
  const char *hdr_end = strchr(hdr_start, '\n');
  if (!hdr_end) return -1;
  size_t hdr_len = (size_t)(hdr_end - hdr_start);
  char *hdr = malloc(hdr_len + 1);
  if (!hdr) return -1;
  memcpy(hdr, hdr_start, hdr_len); hdr[hdr_len] = '\0';

  char *cols[16]; int colc = 0;
  char *tmp = strdup(hdr);
  if (tmp) {
    char *tk = strtok(tmp, "\t");
    if (!tk) tk = strtok(tmp, " \t");
    while (tk && colc < (int)(sizeof(cols)/sizeof(cols[0]))) { cols[colc++] = tk; tk = strtok(NULL, "\t"); if (!tk) tk = strtok(NULL, " \t"); }
  }
  int idx_local=-1, idx_remote=-1, idx_lq=-1, idx_nlq=-1, idx_cost=-1, idx_intf=-1;
  for (int i=0;i<colc;i++){
    char low[128]; size_t L = strlen(cols[i]); if (L >= sizeof(low)) L = sizeof(low)-1; for (size_t j=0;j<L;j++) low[j] = (char)tolower((unsigned char)cols[i][j]); low[L]=0;
    if (strstr(low, "local") != NULL || strstr(low, "local ip") != NULL) idx_local = i;
    if (strstr(low, "remote") != NULL || strstr(low, "remote ip") != NULL) idx_remote = i;
    if (strstr(low, "lq") != NULL && idx_lq==-1) idx_lq = i;
    if (strstr(low, "nlq") != NULL && idx_nlq==-1) idx_nlq = i;
    if (strstr(low, "cost") != NULL && idx_cost==-1) idx_cost = i;
    if (strstr(low, "intf") != NULL || strstr(low, "interface") != NULL) idx_intf = i;
  }

  p = hdr_end; if (*p=='\n') p++;
  size_t cap = 4096; size_t len = 0; char *buf = NULL;
  json_buf_append(&buf,&len,&cap,"["); int first = 1;
  while (*p && *p != '\0') {
    if (strncmp(p, "Table:", 6) == 0) break;
    const char *lnend = strchr(p, '\n'); if (!lnend) lnend = p + strlen(p);
    size_t lsz = (size_t)(lnend - p);
    if (lsz == 0 || (lsz==1 && p[0]=='\r')) { p = (*lnend=='\n') ? lnend+1 : lnend; continue; }
    char *row = malloc(lsz+1); if (!row) break; memcpy(row, p, lsz); row[lsz]=0;
    while (lsz > 0 && (row[lsz-1] == '\r' || row[lsz-1] == '\n')) { row[--lsz] = '\0'; }
    char *fields[16]; int f = 0;
    char *rtmp = row;
    char *tk = strtok(rtmp, "\t");
    if (!tk) tk = strtok(rtmp, " \t");
    while (tk && f < (int)(sizeof(fields)/sizeof(fields[0]))) { fields[f++] = tk; tk = strtok(NULL, "\t"); if (!tk) tk = strtok(NULL, " \t"); }
    if (f >= 2) {
      char *local = NULL, *remote = NULL, *lq = NULL, *nlq = NULL, *cost = NULL, *intf = NULL;
      local = (idx_local >= 0 && idx_local < f) ? fields[idx_local] : fields[0];
      remote = (idx_remote >= 0 && idx_remote < f) ? fields[idx_remote] : (f>1?fields[1]:"");
      lq = (idx_lq >= 0 && idx_lq < f) ? fields[idx_lq] : "";
      nlq = (idx_nlq >= 0 && idx_nlq < f) ? fields[idx_nlq] : "";
      cost = (idx_cost >= 0 && idx_cost < f) ? fields[idx_cost] : "";
      intf = (idx_intf >= 0 && idx_intf < f) ? fields[idx_intf] : "";
      strip_tags_and_trim(local); strip_tags_and_trim(remote); strip_tags_and_trim(lq); strip_tags_and_trim(nlq); strip_tags_and_trim(cost); strip_tags_and_trim(intf);
      /* Heuristic route/node counting by scanning combined raw for routes/topology entries.
       * If caller passed a combined document (links + routes + topology), we'll try to
       * count routes via gateway occurrences and nodes via lastHop/lastHopIP occurrences.
       */
      int routes_count = 0;
      int nodes_count = 0;
      if (raw && remote && remote[0]) {
        /* count occurrences of gateway JSON fragments: "gateway":"<remote> */
        char pat_gw[128]; snprintf(pat_gw, sizeof(pat_gw), "\"gateway\":\"%s", remote);
        const char *sr = raw; int safety = 0;
        while ((sr = strstr(sr, pat_gw)) && safety < 100000) { routes_count++; sr += strlen(pat_gw); safety++; }
        /* also count plain-tabbed route lines where second column equals remote (Table: Routes tab format)
         * Format: Destination\tGateway IP\tMetric\tETX\tInterface
         */
        const char *routes_tbl = strstr(raw, "Table: Routes");
        if (routes_tbl) {
          const char *rt = routes_tbl;
          /* skip header line */
          const char *h = strchr(rt, '\n'); if (h) rt = h + 1; else rt = rt + strlen(rt);
          while (rt && *rt && strncmp(rt, "Table:", 6) != 0) {
            const char *lnend_rt = strchr(rt, '\n'); if (!lnend_rt) lnend_rt = rt + strlen(rt);
            size_t lsz2 = (size_t)(lnend - rt);
            if (lsz2 > 0) {
              char *line2 = malloc(lsz2 + 1);
              if (line2) {
                memcpy(line2, rt, lsz2); line2[lsz2] = '\0';
                /* split by tabs or spaces; we only need the second field */
                char *tmp2 = strdup(line2);
                if (tmp2) {
                  char *tk2 = strtok(tmp2, "\t"); if (!tk2) tk2 = strtok(tmp2, " \t"); if (tk2) { tk2 = strtok(NULL, "\t"); if (!tk2) tk2 = strtok(NULL, " \t"); }
                  if (tk2 && strcmp(tk2, remote) == 0) routes_count++;
                  free(tmp2);
                }
                free(line2);
              }
            }
            if (*lnend_rt == '\0') { break; } else { rt = lnend_rt + 1; }
          }
        }
        /* nodes: look for lastHopIP / lastHop JSON fragments or topology table lines
         * We count unique destination IPs where lastHop == remote to approximate nodes.
         */
        char pattern_lh[128]; snprintf(pattern_lh, sizeof(pattern_lh), "\"lastHopIP\":\"%s", remote);
  sr = raw; safety = 0;
        while ((sr = strstr(sr, pattern_lh)) && safety < 100000) { nodes_count++; sr += strlen(pattern_lh); safety++; }
        /* topology table scan (Tab-separated: Dest. IP\tLast hop IP\t...) */
        const char *top_tbl = strstr(raw, "Table: Topology");
        if (top_tbl) {
          const char *tt = top_tbl;
          const char *h2 = strchr(tt, '\n'); if (h2) tt = h2 + 1; else tt = tt + strlen(tt);
          /* simple set of unique destinations per remote (cap small) */
          char *uniq[512]; int ucnt = 0;
          while (tt && *tt && strncmp(tt, "Table:", 6) != 0) {
            const char *lnend_tt = strchr(tt, '\n'); if (!lnend_tt) lnend_tt = tt + strlen(tt);
            size_t lsz2 = (size_t)(lnend - tt);
            if (lsz2 > 0) {
              char *line2 = malloc(lsz2 + 1);
              if (line2) {
                memcpy(line2, tt, lsz2); line2[lsz2] = '\0';
                char *tmp2 = strdup(line2);
                if (tmp2) {
                  /* fields: dest\tlastHop\t... */
                  char *tk2 = strtok(tmp2, "\t"); char *destf = tk2; char *lhoff = NULL;
                  if (tk2) { tk2 = strtok(NULL, "\t"); if (tk2) lhoff = tk2; }
                  if (destf && lhoff && strcmp(lhoff, remote) == 0) {
                    /* ensure uniqueness */
                    int dup = 0; for (int i=0;i<ucnt;i++) if (strcmp(uniq[i], destf) == 0) { dup = 1; break; }
                    if (!dup && ucnt < (int)(sizeof(uniq)/sizeof(uniq[0]))) { uniq[ucnt++] = strdup(destf); }
                  }
                  free(tmp2);
                }
                free(line2);
              }
            }
            if (*lnend_tt == '\0') { break; } else { tt = lnend_tt + 1; }
          }
          nodes_count += ucnt;
          for (int i=0;i<ucnt;i++) if (uniq[i]) free(uniq[i]);
        }
      }
      if (!first) { json_buf_append(&buf,&len,&cap,","); } first = 0;
      char remote_host[512] = "";
      if (remote && remote[0]) {
        lookup_hostname_cached(remote, remote_host, sizeof(remote_host));
      }
      json_buf_append(&buf,&len,&cap,"{\"intf\":"); json_append_escaped(&buf,&len,&cap,intf?intf:"");
      json_buf_append(&buf,&len,&cap,",\"local\":"); json_append_escaped(&buf,&len,&cap,local?local:"");
      json_buf_append(&buf,&len,&cap,",\"remote\":"); json_append_escaped(&buf,&len,&cap,remote?remote:"");
      json_buf_append(&buf,&len,&cap,",\"remote_host\":"); json_append_escaped(&buf,&len,&cap,remote_host);
      json_buf_append(&buf,&len,&cap,",\"lq\":"); json_append_escaped(&buf,&len,&cap,lq?lq:"");
      json_buf_append(&buf,&len,&cap,",\"nlq\":"); json_append_escaped(&buf,&len,&cap,nlq?nlq:"");
      json_buf_append(&buf,&len,&cap,",\"cost\":"); json_append_escaped(&buf,&len,&cap,cost?cost:"");
      /* emit computed counts (as strings for compatibility) */
      {
        char routes_s[16]; snprintf(routes_s, sizeof(routes_s), "%d", routes_count);
        char nodes_s[16]; snprintf(nodes_s, sizeof(nodes_s), "%d", nodes_count);
        json_buf_append(&buf,&len,&cap,",\"routes\":"); json_append_escaped(&buf,&len,&cap,routes_s);
        json_buf_append(&buf,&len,&cap,",\"nodes\":"); json_append_escaped(&buf,&len,&cap,nodes_s);
      }
      json_buf_append(&buf,&len,&cap,",\"is_default\":false}");
    }
    free(row);
    if (*lnend == '\0') {
      break;
    }
    p = lnend + 1;
  }
  json_buf_append(&buf,&len,&cap,"]");
  *outbuf = buf;
  *outlen = len;
  if (hdr) free(hdr);
  if (tmp) free(tmp);
  return 0;
}

int normalize_olsrd_neighbors_plain(const char *raw, char **outbuf, size_t *outlen) {
  if (!raw || !outbuf || !outlen) return -1;
  *outbuf = NULL; *outlen = 0;
  const char *tbl = strstr(raw, "Table: Neighbors");
  if (!tbl) return -1;
  const char *p = tbl;
  while (*p && *p != '\n') p++;
  if (*p == '\n') p++;
  const char *hdr_start = p;
  const char *hdr_end = strchr(hdr_start, '\n');
  if (!hdr_end) return -1;
  size_t hdr_len = (size_t)(hdr_end - hdr_start);
  char *hdr = malloc(hdr_len + 1);
  if (!hdr) return -1;
  memcpy(hdr, hdr_start, hdr_len); hdr[hdr_len] = '\0';

  p = hdr_end; if (*p=='\n') p++;
  size_t cap = 4096; size_t len = 0; char *buf = NULL;
  json_buf_append(&buf,&len,&cap,"["); int first = 1;
  while (*p && *p != '\0') {
    if (strncmp(p, "Table:", 6) == 0) break;
    const char *lnend = strchr(p, '\n'); if (!lnend) lnend = p + strlen(p);
    size_t lsz = (size_t)(lnend - p);
    if (lsz == 0 || (lsz==1 && p[0]=='\r')) { p = (*lnend=='\n') ? lnend+1 : lnend; continue; }
    char *row = malloc(lsz+1); if (!row) break; memcpy(row, p, lsz); row[lsz]=0;
    while (lsz > 0 && (row[lsz-1] == '\r' || row[lsz-1] == '\n')) { row[--lsz] = '\0'; }
    char *fields[16]; int f = 0;
    char *rtmp = row;
    char *tk = strtok(rtmp, "\t");
    if (!tk) tk = strtok(rtmp, " \t");
    while (tk && f < (int)(sizeof(fields)/sizeof(fields[0]))) { fields[f++] = tk; tk = strtok(NULL, "\t"); if (!tk) tk = strtok(NULL, " \t"); }
    if (f >= 6) {
      char *originator = fields[0];
      char *sym = fields[1];
      char *mpr = fields[2];
      char *mprs = fields[3];
      char *willingness = fields[4];
      char *twoHopCount = fields[5];
      strip_tags_and_trim(originator); strip_tags_and_trim(sym); strip_tags_and_trim(mpr); strip_tags_and_trim(mprs); strip_tags_and_trim(willingness); strip_tags_and_trim(twoHopCount);
      if (!first) json_buf_append(&buf,&len,&cap,",");
      json_buf_append(&buf,&len,&cap,"{\"originator\":"); json_append_escaped(&buf,&len,&cap,originator?originator:"");
      json_buf_append(&buf,&len,&cap,",\"sym\":"); json_append_escaped(&buf,&len,&cap,sym?sym:"");
      json_buf_append(&buf,&len,&cap,",\"mpr\":"); json_append_escaped(&buf,&len,&cap,mpr?mpr:"");
      json_buf_append(&buf,&len,&cap,",\"mprs\":"); json_append_escaped(&buf,&len,&cap,mprs?mprs:"");
      json_buf_append(&buf,&len,&cap,",\"willingness\":"); json_append_escaped(&buf,&len,&cap,willingness?willingness:"");
      json_buf_append(&buf,&len,&cap,",\"twoHopCount\":"); json_append_escaped(&buf,&len,&cap,twoHopCount?twoHopCount:"");
      json_buf_append(&buf,&len,&cap,"}");
      first = 0;
    }
    free(row);
    p = lnend + 1;
  }
  json_buf_append(&buf,&len,&cap,"]");
  *outbuf = buf;
  *outlen = len;
  if (hdr) free(hdr);
  return 0;
}

int normalize_olsrd_routes_plain(const char *raw, char **outbuf, size_t *outlen) {
  if (!raw || !outbuf || !outlen) return -1;
  *outbuf = NULL; *outlen = 0;
  const char *tbl = strstr(raw, "Table: Routes");
  if (!tbl) return -1;
  const char *p = tbl;
  while (*p && *p != '\n') p++;
  if (*p == '\n') p++;
  const char *hdr_start = p;
  const char *hdr_end = strchr(hdr_start, '\n');
  if (!hdr_end) return -1;
  size_t hdr_len = (size_t)(hdr_end - hdr_start);
  char *hdr = malloc(hdr_len + 1);
  if (!hdr) return -1;
  memcpy(hdr, hdr_start, hdr_len); hdr[hdr_len] = '\0';

  p = hdr_end; if (*p=='\n') p++;
  size_t cap = 4096; size_t len = 0; char *buf = NULL;
  json_buf_append(&buf,&len,&cap,"["); int first = 1;
  while (*p && *p != '\0') {
    if (strncmp(p, "Table:", 6) == 0) break;
    const char *lnend = strchr(p, '\n'); if (!lnend) lnend = p + strlen(p);
    size_t lsz = (size_t)(lnend - p);
    if (lsz == 0 || (lsz==1 && p[0]=='\r')) { p = (*lnend=='\n') ? lnend+1 : lnend; continue; }
    char *row = malloc(lsz+1); if (!row) break; memcpy(row, p, lsz); row[lsz]=0;
    while (lsz > 0 && (row[lsz-1] == '\r' || row[lsz-1] == '\n')) { row[--lsz] = '\0'; }
    char *fields[16]; int f = 0;
    char *rtmp = row;
    char *tk = strtok(rtmp, "\t");
    if (!tk) tk = strtok(rtmp, " \t");
    while (tk && f < (int)(sizeof(fields)/sizeof(fields[0]))) { fields[f++] = tk; tk = strtok(NULL, "\t"); if (!tk) tk = strtok(NULL, " \t"); }
    if (f >= 5) {
      char *destination = fields[0];
      char *gateway = fields[1];
      char *metric = fields[2];
      char *etx = fields[3];
      char *interface = fields[4];
      strip_tags_and_trim(destination); strip_tags_and_trim(gateway); strip_tags_and_trim(metric); strip_tags_and_trim(etx); strip_tags_and_trim(interface);
      if (!first) json_buf_append(&buf,&len,&cap,",");
      json_buf_append(&buf,&len,&cap,"{\"destination\":"); json_append_escaped(&buf,&len,&cap,destination?destination:"");
      json_buf_append(&buf,&len,&cap,",\"gateway\":"); json_append_escaped(&buf,&len,&cap,gateway?gateway:"");
      json_buf_append(&buf,&len,&cap,",\"metric\":"); json_append_escaped(&buf,&len,&cap,metric?metric:"");
      json_buf_append(&buf,&len,&cap,",\"etx\":"); json_append_escaped(&buf,&len,&cap,etx?etx:"");
      json_buf_append(&buf,&len,&cap,",\"interface\":"); json_append_escaped(&buf,&len,&cap,interface?interface:"");
      json_buf_append(&buf,&len,&cap,"}");
      first = 0;
    }
    free(row);
    p = lnend + 1;
  }
  json_buf_append(&buf,&len,&cap,"]");
  *outbuf = buf;
  *outlen = len;
  if (hdr) free(hdr);
  return 0;
}

int normalize_olsrd_topology_plain(const char *raw, char **outbuf, size_t *outlen) {
  if (!raw || !outbuf || !outlen) return -1;
  *outbuf = NULL; *outlen = 0;
  const char *tbl = strstr(raw, "Table: Topology");
  if (!tbl) return -1;
  const char *p = tbl;
  while (*p && *p != '\n') p++;
  if (*p == '\n') p++;
  const char *hdr_start = p;
  const char *hdr_end = strchr(hdr_start, '\n');
  if (!hdr_end) return -1;
  size_t hdr_len = (size_t)(hdr_end - hdr_start);
  char *hdr = malloc(hdr_len + 1);
  if (!hdr) return -1;
  memcpy(hdr, hdr_start, hdr_len); hdr[hdr_len] = '\0';

  p = hdr_end; if (*p=='\n') p++;
  size_t cap = 4096; size_t len = 0; char *buf = NULL;
  json_buf_append(&buf,&len,&cap,"["); int first = 1;
  while (*p && *p != '\0') {
    if (strncmp(p, "Table:", 6) == 0) break;
    const char *lnend = strchr(p, '\n'); if (!lnend) lnend = p + strlen(p);
    size_t lsz = (size_t)(lnend - p);
    if (lsz == 0 || (lsz==1 && p[0]=='\r')) { p = (*lnend=='\n') ? lnend+1 : lnend; continue; }
    char *row = malloc(lsz+1); if (!row) break; memcpy(row, p, lsz); row[lsz]=0;
    while (lsz > 0 && (row[lsz-1] == '\r' || row[lsz-1] == '\n')) { row[--lsz] = '\0'; }
    char *fields[16]; int f = 0;
    char *rtmp = row;
    char *tk = strtok(rtmp, "\t");
    if (!tk) tk = strtok(rtmp, " \t");
    while (tk && f < (int)(sizeof(fields)/sizeof(fields[0]))) { fields[f++] = tk; tk = strtok(NULL, "\t"); if (!tk) tk = strtok(NULL, " \t"); }
    if (f >= 5) {
      char *destinationIP = fields[0];
      char *lastHopIP = fields[1];
      char *lq = fields[2];
      char *nlq = fields[3];
      char *cost = fields[4];
      strip_tags_and_trim(destinationIP); strip_tags_and_trim(lastHopIP); strip_tags_and_trim(lq); strip_tags_and_trim(nlq); strip_tags_and_trim(cost);
      if (!first) json_buf_append(&buf,&len,&cap,",");
      json_buf_append(&buf,&len,&cap,"{\"destinationIP\":"); json_append_escaped(&buf,&len,&cap,destinationIP?destinationIP:"");
      json_buf_append(&buf,&len,&cap,",\"lastHopIP\":"); json_append_escaped(&buf,&len,&cap,lastHopIP?lastHopIP:"");
      json_buf_append(&buf,&len,&cap,",\"lq\":"); json_append_escaped(&buf,&len,&cap,lq?lq:"");
      json_buf_append(&buf,&len,&cap,",\"nlq\":"); json_append_escaped(&buf,&len,&cap,nlq?nlq:"");
      json_buf_append(&buf,&len,&cap,",\"cost\":"); json_append_escaped(&buf,&len,&cap,cost?cost:"");
      json_buf_append(&buf,&len,&cap,"}");
      first = 0;
    }
    free(row);
    p = lnend + 1;
  }
  json_buf_append(&buf,&len,&cap,"]");
  *outbuf = buf;
  *outlen = len;
  if (hdr) free(hdr);
  return 0;
}
