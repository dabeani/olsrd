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

/* Minimal dynamic JSON buffer helpers */
static int json_buf_append(char **bufptr, size_t *lenptr, size_t *capptr, const char *fmt, ...) {
  va_list ap; char *t = NULL; int n;
  va_start(ap, fmt);
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
  n = vasprintf(&t, fmt, ap);
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
  va_end(ap);
  if (n < 0 || !t) return -1;
  if (*bufptr == NULL) {
    *capptr = (size_t)n + 128;
    *bufptr = malloc(*capptr);
    if (!*bufptr) { free(t); return -1; }
    (*bufptr)[0] = '\0'; *lenptr = 0;
  }
  if (*lenptr + (size_t)n + 1 > *capptr) {
    size_t need = *lenptr + (size_t)n + 1;
    size_t nc = *capptr * 2;
    if (nc < need) nc = need + 128;
    char *nb = realloc(*bufptr, nc);
    if (!nb) { free(t); return -1; }
    *bufptr = nb; *capptr = nc;
  }
  memcpy(*bufptr + *lenptr, t, (size_t)n);
  *lenptr += (size_t)n; (*bufptr)[*lenptr] = '\0';
  free(t);
  return 0;
}

static int json_append_escaped(char **bufptr, size_t *lenptr, size_t *capptr, const char *s) {
  if (!s) return json_buf_append(bufptr, lenptr, capptr, "\"\"");
  if (json_buf_append(bufptr, lenptr, capptr, "\"") < 0) return -1;
  for (const unsigned char *p = (const unsigned char*)s; *p; ++p) {
    unsigned char c = *p;
    switch (c) {
      case '"': if (json_buf_append(bufptr,lenptr,capptr,"\\\"")<0) return -1; break;
      case '\\': if (json_buf_append(bufptr,lenptr,capptr,"\\\\")<0) return -1; break;
      case '\b': if (json_buf_append(bufptr,lenptr,capptr,"\\b")<0) return -1; break;
      case '\f': if (json_buf_append(bufptr,lenptr,capptr,"\\f")<0) return -1; break;
      case '\n': if (json_buf_append(bufptr,lenptr,capptr,"\\n")<0) return -1; break;
      case '\r': if (json_buf_append(bufptr,lenptr,capptr,"\\r")<0) return -1; break;
      case '\t': if (json_buf_append(bufptr,lenptr,capptr,"\\t")<0) return -1; break;
      default:
        if (c < 0x20) {
          if (json_buf_append(bufptr,lenptr,capptr,"\\u%04x", c)<0) return -1;
        } else {
          char t[2] = { (char)c, 0 };
          if (json_buf_append(bufptr,lenptr,capptr, "%s", t) < 0) return -1;
        }
    }
  }
  if (json_buf_append(bufptr, lenptr, capptr, "\"") < 0) return -1;
  return 0;
}

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
      if (!first) { json_buf_append(&buf,&len,&cap,","); } first = 0;
      json_buf_append(&buf,&len,&cap,"{\"intf\":"); json_append_escaped(&buf,&len,&cap,intf?intf:"");
      json_buf_append(&buf,&len,&cap,",\"local\":"); json_append_escaped(&buf,&len,&cap,local?local:"");
      json_buf_append(&buf,&len,&cap,",\"remote\":"); json_append_escaped(&buf,&len,&cap,remote?remote:"");
      json_buf_append(&buf,&len,&cap,",\"remote_host\":\"\"");
      json_buf_append(&buf,&len,&cap,",\"lq\":"); json_append_escaped(&buf,&len,&cap,lq?lq:"");
      json_buf_append(&buf,&len,&cap,",\"nlq\":"); json_append_escaped(&buf,&len,&cap,nlq?nlq:"");
      json_buf_append(&buf,&len,&cap,",\"cost\":"); json_append_escaped(&buf,&len,&cap,cost?cost:"");
      json_buf_append(&buf,&len,&cap,",\"routes\":\"0\",\"nodes\":\"0\",\"is_default\":false}");
    }
    free(row);
    if (*lnend == '\0') break; p = lnend + 1;
  }
  json_buf_append(&buf,&len,&cap,"]"); *outbuf = buf; *outlen = len;
  if (hdr) free(hdr); if (tmp) free(tmp);
  return 0;
}
