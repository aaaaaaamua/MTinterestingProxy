#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "common/db-utils.h"
#include "common/kprintf.h"

struct db_config proxy_db_config = {
  .host = "localhost",
  .port = 7878,
  .user = "root",
  .pwd = NULL,
  .name = "mtproxy_billing"
};

static MYSQL *conn = NULL;

void db_init (void) {
  conn = mysql_init (NULL);
  if (conn == NULL) {
    kprintf ("Error: mysql_init failed\n");
    return;
  }

  if (mysql_real_connect (conn, proxy_db_config.host, proxy_db_config.user, 
                          proxy_db_config.pwd, proxy_db_config.name, 
                          proxy_db_config.port, NULL, 0) == NULL) {
    kprintf ("Error: mysql_real_connect failed: %s\n", mysql_error (conn));
    mysql_close (conn);
    conn = NULL;
    return;
  }
  kprintf ("MySQL connected to %s:%d\n", proxy_db_config.host, proxy_db_config.port);
}

// External function from net-tcp-rpc-ext-server.c
extern void tcp_rpcs_clear_secrets (void);
extern void tcp_rpcs_add_secret_from_db (const char *hex_secret, const char *bound_ip);

void db_sync_secrets (void) {
  if (!conn) {
    db_init ();
    if (!conn) return;
  }

  if (mysql_query (conn, "SELECT secret_hex, bound_ip FROM secrets WHERE is_active=1")) {
    kprintf ("Error: mysql_query failed: %s\n", mysql_error (conn));
    return;
  }

  MYSQL_RES *res = mysql_store_result (conn);
  if (!res) return;

  tcp_rpcs_clear_secrets ();

  MYSQL_ROW row;
  while ((row = mysql_fetch_row (res))) {
    tcp_rpcs_add_secret_from_db (row[0], row[1]);
  }

  mysql_free_result (res);
}

static void *db_sync_thread_main (void *arg) {
  while (1) {
    db_sync_secrets ();
    sleep (10); // Sync every 10 seconds
  }
  return NULL;
}

void db_start_sync_thread (void) {
  pthread_t tid;
  if (pthread_create (&tid, NULL, db_sync_thread_main, NULL)) {
    kprintf ("Error: pthread_create for db_sync failed\n");
  } else {
    pthread_detach (tid);
  }
}
