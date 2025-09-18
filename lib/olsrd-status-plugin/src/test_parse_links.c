#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int normalize_olsrd_links_plain(const char *raw, char **outbuf, size_t *outlen);

int main(int argc, char **argv) {
  const char *path = "/tmp/olsr_remote.txt";
  if (argc > 1) path = argv[1];
  FILE *f = fopen(path, "rb");
  if (!f) { perror("fopen"); return 2; }
  fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
  char *buf = malloc((size_t)sz + 1); if (!buf) { fclose(f); return 3; }
  if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { perror("fread"); free(buf); fclose(f); return 4; }
  buf[sz] = '\0'; fclose(f);
  char *out = NULL; size_t n = 0;
  if (normalize_olsrd_links_plain(buf, &out, &n) == 0 && out) {
    printf("OUTPUT (len=%zu):\n%s\n", n, out);
    free(out);
  } else {
    fprintf(stderr, "parse failed\n");
    free(buf);
    return 5;
  }
  free(buf);
  return 0;
}
