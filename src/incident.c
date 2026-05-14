#include "mkdbg.h"

void sanitize_slug(const char *input, char *out, size_t out_size)
{
  size_t j = 0U;
  size_t i;
  int prev_dash = 0;

  for (i = 0; input != NULL && input[i] != '\0'; ++i) {
    unsigned char ch = (unsigned char)input[i];
    if (isalnum(ch)) {
      if (j + 1U < out_size) {
        out[j++] = (char)tolower(ch);
      }
      prev_dash = 0;
    } else if ((ch == '-' || ch == '_' || isspace(ch)) && !prev_dash) {
      if (j + 1U < out_size) {
        out[j++] = '-';
      }
      prev_dash = 1;
    }
  }

  while (j > 0U && out[j - 1U] == '-') {
    j--;
  }
  if (j == 0U && out_size > 1U) {
    copy_string(out, out_size, "incident");
    return;
  }
  out[j] = '\0';
}

int load_current_incident_id(const char *config_path, char *out, size_t out_size)
{
  char current_path[PATH_MAX];
  FILE *f;

  current_incident_path_from_config(config_path, current_path, sizeof(current_path));
  if (!path_exists(current_path)) {
    return -1;
  }
  f = fopen(current_path, "r");
  if (f == NULL) {
    return -1;
  }
  if (fgets(out, (int)out_size, f) == NULL) {
    fclose(f);
    return -1;
  }
  fclose(f);
  trim_in_place(out);
  return (out[0] == '\0') ? -1 : 0;
}

int load_incident_metadata(const char *meta_path, IncidentMetadata *meta)
{
  FILE *f;
  char line[512];

  memset(meta, 0, sizeof(*meta));
  f = fopen(meta_path, "r");
  if (f == NULL) {
    return -1;
  }
  while (fgets(line, sizeof(line), f) != NULL) {
    char *colon = strchr(line, ':');
    char *value;
    size_t len;
    if (colon == NULL) {
      continue;
    }
    *colon = '\0';
    trim_in_place(line);
    value = colon + 1;
    trim_in_place(value);
    len = strlen(value);
    if (len > 0U && value[len - 1U] == ',') {
      value[len - 1U] = '\0';
      trim_in_place(value);
    }
    if (strcmp(line, "\"id\"") == 0) parse_quoted_value(value, meta->id, sizeof(meta->id));
    else if (strcmp(line, "\"name\"") == 0) parse_quoted_value(value, meta->name, sizeof(meta->name));
    else if (strcmp(line, "\"status\"") == 0) parse_quoted_value(value, meta->status, sizeof(meta->status));
    else if (strcmp(line, "\"repo\"") == 0) parse_quoted_value(value, meta->repo, sizeof(meta->repo));
    else if (strcmp(line, "\"port\"") == 0) parse_quoted_value(value, meta->port, sizeof(meta->port));
    else if (strcmp(line, "\"opened_at\"") == 0) meta->opened_at = atol(value);
  }
  fclose(f);
  return 0;
}

int write_incident_metadata(const char *meta_path, const IncidentMetadata *meta, long closed_at)
{
  FILE *f = fopen(meta_path, "w");
  if (f == NULL) {
    return -1;
  }
  fprintf(f,
          "{\n"
          "  \"id\": \"%s\",\n"
          "  \"name\": \"%s\",\n"
          "  \"status\": \"%s\",\n"
          "  \"repo\": \"%s\",\n"
          "  \"port\": \"%s\",\n"
          "  \"opened_at\": %ld",
          meta->id, meta->name, meta->status, meta->repo, meta->port, meta->opened_at);
  if (closed_at > 0L) {
    fprintf(f, ",\n  \"closed_at\": %ld", closed_at);
  }
  fprintf(f, "\n}\n");
  fclose(f);
  return 0;
}

int load_current_incident_dir(const char *config_path, char *out, size_t out_size)
{
  char incident_id[MAX_NAME];
  char incidents_root[PATH_MAX];

  if (load_current_incident_id(config_path, incident_id, sizeof(incident_id)) != 0) {
    return -1;
  }
  incidents_root_from_config(config_path, incidents_root, sizeof(incidents_root));
  join_path(incidents_root, incident_id, out, out_size);
  return 0;
}

int cmd_incident_open(const IncidentOpenOptions *opts)
{
  char config_path[PATH_MAX];
  char incidents_root[PATH_MAX];
  char current_path[PATH_MAX];
  char current_id[MAX_NAME];
  char incident_id[MAX_NAME];
  char incident_dir[PATH_MAX];
  char meta_path[PATH_MAX];
  char slug[MAX_NAME];
  const char *repo_name;
  MkdbgConfig config;
  const RepoConfig *repo;
  FILE *f;
  IncidentMetadata meta;

  if (find_config_upward(config_path, sizeof(config_path)) != 0) {
    die("missing %s; run `mkdbg init` first", CONFIG_NAME);
  }
  if (load_config_file(config_path, &config) != 0) {
    die("invalid config: %s", config_path);
  }
  resolve_repo_name(&config, opts->repo, opts->target, &repo_name);
  repo = find_repo_const(&config, repo_name);
  if (repo == NULL) {
    die("repo `%s` not found in %s", repo_name, config_path);
  }

  if (load_current_incident_id(config_path, current_id, sizeof(current_id)) == 0) {
    die("incident `%s` is already active; close it first", current_id);
  }

  incidents_root_from_config(config_path, incidents_root, sizeof(incidents_root));
  current_incident_path_from_config(config_path, current_path, sizeof(current_path));
  state_root_from_config(config_path, incident_dir, sizeof(incident_dir));
  if (ensure_dir(incident_dir) != 0 || ensure_dir(incidents_root) != 0) {
    die("failed to create incident state directories");
  }

  sanitize_slug(opts->name != NULL ? opts->name : repo_name, slug, sizeof(slug));
  incident_id[0] = '\0';
  {
    char tsbuf[32];
    snprintf(tsbuf, sizeof(tsbuf), "%ld", (long)time(NULL));
    copy_string(incident_id, sizeof(incident_id), tsbuf);
  }
  append_string(incident_id, sizeof(incident_id), "-");
  append_string(incident_id, sizeof(incident_id), slug);
  join_path(incidents_root, incident_id, incident_dir, sizeof(incident_dir));
  if (ensure_dir(incident_dir) != 0) {
    die("failed to create incident directory: %s", incident_dir);
  }

  memset(&meta, 0, sizeof(meta));
  copy_string(meta.id, sizeof(meta.id), incident_id);
  copy_string(meta.name, sizeof(meta.name), opts->name != NULL ? opts->name : repo_name);
  copy_string(meta.status, sizeof(meta.status), "open");
  copy_string(meta.repo, sizeof(meta.repo), repo_name);
  copy_string(meta.port, sizeof(meta.port), opts->port != NULL ? opts->port : repo->port);
  meta.opened_at = (long)time(NULL);

  incident_meta_path(incident_dir, meta_path, sizeof(meta_path));
  if (write_incident_metadata(meta_path, &meta, 0L) != 0) {
    die("failed to write incident metadata");
  }

  f = fopen(current_path, "w");
  if (f == NULL) {
    die("failed to write current incident marker");
  }
  fprintf(f, "%s\n", incident_id);
  fclose(f);

  printf("incident: %s\n", incident_id);
  printf("path: %s\n", incident_dir);
  printf("repo: %s\n", repo_name);
  if ((opts->port != NULL && opts->port[0] != '\0') || repo->port[0] != '\0') {
    printf("port: %s\n", opts->port != NULL ? opts->port : repo->port);
  }
  return 0;
}

int cmd_incident_status(const IncidentStatusOptions *opts)
{
  char config_path[PATH_MAX];
  char incident_id[MAX_NAME];
  char incidents_root[PATH_MAX];
  char incident_dir[PATH_MAX];
  char meta_path[PATH_MAX];
  IncidentMetadata meta;

  if (find_config_upward(config_path, sizeof(config_path)) != 0) {
    die("missing %s; run `mkdbg init` first", CONFIG_NAME);
  }
  if (load_current_incident_id(config_path, incident_id, sizeof(incident_id)) != 0) {
    if (opts->json) {
      printf("{\"ok\":true,\"active\":false}\n");
    } else {
      printf("incident: none\n");
    }
    return 0;
  }

  incidents_root_from_config(config_path, incidents_root, sizeof(incidents_root));
  join_path(incidents_root, incident_id, incident_dir, sizeof(incident_dir));
  incident_meta_path(incident_dir, meta_path, sizeof(meta_path));
  if (load_incident_metadata(meta_path, &meta) != 0) {
    die("missing incident metadata: %s", meta_path);
  }

  if (opts->json) {
    printf("{\"ok\":true,\"active\":true,\"id\":\"%s\",\"path\":\"%s\",\"name\":\"%s\",\"status\":\"%s\",\"repo\":\"%s\",\"port\":\"%s\",\"opened_at\":%ld}\n",
           incident_id, incident_dir, meta.name, meta.status, meta.repo, meta.port, meta.opened_at);
  } else {
    printf("incident: %s\n", incident_id);
    printf("path: %s\n", incident_dir);
    printf("status: %s\n", meta.status);
    printf("repo: %s\n", meta.repo);
    if (meta.port[0] != '\0') printf("port: %s\n", meta.port);
    printf("opened_at: %ld\n", meta.opened_at);
  }
  return 0;
}

int cmd_incident_close(void)
{
  char config_path[PATH_MAX];
  char current_path[PATH_MAX];
  char incident_id[MAX_NAME];
  char incidents_root[PATH_MAX];
  char incident_dir[PATH_MAX];
  char meta_path[PATH_MAX];
  IncidentMetadata meta;

  if (find_config_upward(config_path, sizeof(config_path)) != 0) {
    die("missing %s; run `mkdbg init` first", CONFIG_NAME);
  }
  if (load_current_incident_id(config_path, incident_id, sizeof(incident_id)) != 0) {
    die("no active incident to close");
  }
  incidents_root_from_config(config_path, incidents_root, sizeof(incidents_root));
  join_path(incidents_root, incident_id, incident_dir, sizeof(incident_dir));
  incident_meta_path(incident_dir, meta_path, sizeof(meta_path));
  if (load_incident_metadata(meta_path, &meta) != 0) {
    die("missing incident metadata: %s", meta_path);
  }
  copy_string(meta.status, sizeof(meta.status), "closed");
  if (write_incident_metadata(meta_path, &meta, (long)time(NULL)) != 0) {
    die("failed to update incident metadata");
  }
  current_incident_path_from_config(config_path, current_path, sizeof(current_path));
  if (unlink(current_path) != 0) {
    die("failed to clear current incident marker");
  }
  printf("closed incident: %s\n", incident_id);
  return 0;
}

static void read_git_rev(const char *repo_root, char *out, size_t out_size)
{
  int pipefd[2];
  pid_t pid;
  ssize_t n;

  copy_string(out, out_size, "unknown");
  if (pipe(pipefd) != 0) {
    return;
  }
  pid = fork();
  if (pid < 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    return;
  }
  if (pid == 0) {
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[1]);
    execlp("git", "git", "-C", repo_root, "rev-parse", "HEAD", (char *)NULL);
    _exit(127);
  }
  close(pipefd[1]);
  n = read(pipefd[0], out, out_size > 0U ? out_size - 1U : 0U);
  close(pipefd[0]);
  wait_for_pid(pid);
  if (n > 0 && out_size > 0U) {
    out[n] = '\0';
    trim_in_place(out);
  }
}

int cmd_incident_export(const IncidentExportOptions *opts)
{
  char config_path[PATH_MAX];
  char incident_id[MAX_NAME];
  char incident_dir[PATH_MAX];
  char meta_path[PATH_MAX];
  char export_dir[PATH_MAX];
  char manifest_path[PATH_MAX];
  char repo_root[PATH_MAX];
  char bundle_path[PATH_MAX];
  char git_rev[64];
  MkdbgConfig config;
  const RepoConfig *repo;
  IncidentMetadata meta;
  FILE *f;

  if (find_config_upward(config_path, sizeof(config_path)) != 0) {
    die("missing %s; run `mkdbg init` first", CONFIG_NAME);
  }
  if (load_config_file(config_path, &config) != 0) {
    die("invalid config: %s", config_path);
  }
  if (load_current_incident_id(config_path, incident_id, sizeof(incident_id)) != 0) {
    die("no active incident to export");
  }
  if (load_current_incident_dir(config_path, incident_dir, sizeof(incident_dir)) != 0) {
    die("failed to resolve active incident directory");
  }
  incident_meta_path(incident_dir, meta_path, sizeof(meta_path));
  if (load_incident_metadata(meta_path, &meta) != 0) {
    die("missing incident metadata: %s", meta_path);
  }
  repo = find_repo_const(&config, meta.repo);
  if (repo == NULL) {
    die("repo `%s` not found in %s", meta.repo, config_path);
  }
  resolve_repo_root(config_path, repo, repo_root, sizeof(repo_root));
  read_git_rev(repo_root, git_rev, sizeof(git_rev));

  if (opts->output != NULL) {
    resolve_path(repo_root, opts->output, export_dir, sizeof(export_dir));
  } else {
    join_path(incident_dir, "export", export_dir, sizeof(export_dir));
  }
  if (ensure_dir(export_dir) != 0) {
    die("failed to create export directory: %s", export_dir);
  }

  join_path(incident_dir, "bundle.json", bundle_path, sizeof(bundle_path));
  join_path(export_dir, "manifest.txt", manifest_path, sizeof(manifest_path));
  f = fopen(manifest_path, "w");
  if (f == NULL) {
    die("failed to write export manifest: %s", manifest_path);
  }
  fprintf(f, "mkdbg incident export\n");
  fprintf(f, "incident_id: %s\n", meta.id);
  fprintf(f, "name: %s\n", meta.name);
  fprintf(f, "status: %s\n", meta.status);
  fprintf(f, "repo: %s\n", meta.repo);
  fprintf(f, "repo_root: %s\n", repo_root);
  fprintf(f, "git_rev: %s\n", git_rev);
  fprintf(f, "config: %s\n", config_path);
  fprintf(f, "incident_dir: %s\n", incident_dir);
  fprintf(f, "metadata: %s\n", meta_path);
  if (path_exists(bundle_path)) {
    fprintf(f, "bundle: %s\n", bundle_path);
    fprintf(f, "replay: mkdbg replay %s\n", bundle_path);
  } else {
    fprintf(f, "bundle: <missing>\n");
  }
  if (meta.port[0] != '\0') {
    fprintf(f, "capture: mkdbg capture bundle --port %s\n", meta.port);
  }
  fclose(f);

  printf("export: %s\n", export_dir);
  printf("manifest: %s\n", manifest_path);
  return 0;
}
