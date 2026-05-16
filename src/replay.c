#include "mkdbg.h"

static int read_file_text(const char *path, char *buf, size_t buf_size)
{
  FILE *f;
  size_t n;

  if (buf_size == 0U) return -1;
  f = fopen(path, "rb");
  if (f == NULL) return -1;
  n = fread(buf, 1U, buf_size - 1U, f);
  if (ferror(f)) {
    fclose(f);
    return -1;
  }
  buf[n] = '\0';
  fclose(f);
  return 0;
}

static const char *json_key(const char *buf, const char *key)
{
  char needle[128];
  snprintf(needle, sizeof(needle), "\"%s\":", key);
  return strstr(buf, needle);
}

static void json_string_value(const char *buf, const char *key,
                              char *out, size_t out_size)
{
  const char *p = json_key(buf, key);
  size_t i = 0U;

  if (out_size == 0U) return;
  out[0] = '\0';
  if (p == NULL) return;
  p = strchr(p, ':');
  if (p == NULL) return;
  p++;
  while (*p != '\0' && isspace((unsigned char)*p)) p++;
  if (*p != '"') return;
  p++;
  while (*p != '\0' && *p != '"' && i + 1U < out_size) {
    if (*p == '\\' && p[1] != '\0') p++;
    out[i++] = *p++;
  }
  out[i] = '\0';
}

static int json_int_value(const char *buf, const char *key)
{
  const char *p = json_key(buf, key);
  if (p == NULL) return 0;
  p = strchr(p, ':');
  if (p == NULL) return 0;
  p++;
  while (*p != '\0' && isspace((unsigned char)*p)) p++;
  return atoi(p);
}

int load_bundle_summary(const char *path, BundleSummary *summary)
{
  char buf[16384];

  memset(summary, 0, sizeof(*summary));
  copy_string(summary->path, sizeof(summary->path), path);
  if (read_file_text(path, buf, sizeof(buf)) != 0) {
    return -1;
  }

  summary->halt_signal = json_int_value(buf, "halt_signal");
  summary->timeout = json_int_value(buf, "timeout");
  json_string_value(buf, "pc", summary->pc, sizeof(summary->pc));
  json_string_value(buf, "lr", summary->lr, sizeof(summary->lr));
  json_string_value(buf, "sp", summary->sp, sizeof(summary->sp));
  json_string_value(buf, "cfsr", summary->cfsr, sizeof(summary->cfsr));
  json_string_value(buf, "cfsr_decoded", summary->cfsr_decoded,
                    sizeof(summary->cfsr_decoded));
  return 0;
}

int cmd_replay(const ReplayOptions *opts)
{
  BundleSummary s;
  if (load_bundle_summary(opts->bundle, &s) != 0) {
    fprintf(stderr, "mkdbg: replay: cannot read %s\n", opts->bundle);
    return 1;
  }

  if (opts->json) {
    printf("{\"bundle\":\"%s\",\"halt_signal\":%d,\"timeout\":%d,"
           "\"pc\":\"%s\",\"lr\":\"%s\",\"sp\":\"%s\",\"cfsr\":\"%s\"}\n",
           s.path, s.halt_signal, s.timeout, s.pc, s.lr, s.sp, s.cfsr);
    return 0;
  }

  printf("bundle: %s\n", s.path);
  printf("halt_signal: %d\n", s.halt_signal);
  printf("timeout: %d\n", s.timeout);
  printf("pc: %s\n", s.pc[0] ? s.pc : "unknown");
  printf("lr: %s\n", s.lr[0] ? s.lr : "unknown");
  printf("sp: %s\n", s.sp[0] ? s.sp : "unknown");
  printf("cfsr: %s\n", s.cfsr[0] ? s.cfsr : "unknown");
  if (s.cfsr_decoded[0] != '\0') {
    printf("cfsr_decoded: %s\n", s.cfsr_decoded);
  }
  return 0;
}

int cmd_diff(const DiffOptions *opts)
{
  BundleSummary a;
  BundleSummary b;
  int changed = 0;

  if (load_bundle_summary(opts->left, &a) != 0) {
    fprintf(stderr, "mkdbg: diff: cannot read %s\n", opts->left);
    return 1;
  }
  if (load_bundle_summary(opts->right, &b) != 0) {
    fprintf(stderr, "mkdbg: diff: cannot read %s\n", opts->right);
    return 1;
  }

  if (opts->json) {
    printf("{\"left\":\"%s\",\"right\":\"%s\",", a.path, b.path);
    printf("\"halt_signal_changed\":%s,",
           a.halt_signal != b.halt_signal ? "true" : "false");
    printf("\"timeout_changed\":%s,",
           a.timeout != b.timeout ? "true" : "false");
    printf("\"pc_changed\":%s,",
           strcmp(a.pc, b.pc) != 0 ? "true" : "false");
    printf("\"cfsr_changed\":%s}\n",
           strcmp(a.cfsr, b.cfsr) != 0 ? "true" : "false");
    return 0;
  }

  printf("left:  %s\n", a.path);
  printf("right: %s\n", b.path);
  if (a.halt_signal != b.halt_signal) {
    printf("halt_signal: %d -> %d\n", a.halt_signal, b.halt_signal);
    changed = 1;
  }
  if (a.timeout != b.timeout) {
    printf("timeout: %d -> %d\n", a.timeout, b.timeout);
    changed = 1;
  }
  if (strcmp(a.pc, b.pc) != 0) {
    printf("pc: %s -> %s\n", a.pc[0] ? a.pc : "unknown",
           b.pc[0] ? b.pc : "unknown");
    changed = 1;
  }
  if (strcmp(a.lr, b.lr) != 0) {
    printf("lr: %s -> %s\n", a.lr[0] ? a.lr : "unknown",
           b.lr[0] ? b.lr : "unknown");
    changed = 1;
  }
  if (strcmp(a.sp, b.sp) != 0) {
    printf("sp: %s -> %s\n", a.sp[0] ? a.sp : "unknown",
           b.sp[0] ? b.sp : "unknown");
    changed = 1;
  }
  if (strcmp(a.cfsr, b.cfsr) != 0) {
    printf("cfsr: %s -> %s\n", a.cfsr[0] ? a.cfsr : "unknown",
           b.cfsr[0] ? b.cfsr : "unknown");
    changed = 1;
  }
  if (strcmp(a.cfsr_decoded, b.cfsr_decoded) != 0) {
    printf("cfsr_decoded changed\n");
    changed = 1;
  }
  if (!changed) {
    printf("no summary differences\n");
  }
  return 0;
}
