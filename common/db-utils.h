#ifndef __DB_UTILS_H__
#define __DB_UTILS_H__

struct db_config {
  char *host;
  int port;
  char *user;
  char *pwd;
  char *name;
};

extern struct db_config proxy_db_config;

void db_init (void);
void db_sync_secrets (void);
void db_start_sync_thread (void);

#endif
