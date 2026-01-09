#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
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
extern void tcp_rpcs_commit_secrets (void);
extern int tcp_rpcs_get_count (void);
extern int tcp_rpcs_get_secret_id_info (int sid, char *hex_out, unsigned int *ip_out, int *conns_out);
extern void tcp_rpcs_check_keepalive (void);
extern void tcp_rpcs_kick_secret (const char *hex_secret);

// Immediate write-back on handshake
void db_notify_bound_ip (int sid, unsigned int ip) {
    if (!conn) return;
    char hex[33];
    unsigned int dummy_ip;
    int dummy_conns;
    if (tcp_rpcs_get_secret_id_info(sid, hex, &dummy_ip, &dummy_conns)) {
        char query[256];
        char ip_str[INET_ADDRSTRLEN];
        struct in_addr addr;
        addr.s_addr = ip;
        inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
        sprintf(query, "UPDATE secrets SET bound_ip='%s', active_conns=1 WHERE secret_hex='%s'", ip_str, hex);
        mysql_query(conn, query);
    }
}

void db_sync_secrets (void) {
  if (!conn) {
    db_init ();
    if (!conn) return;
  }

  // 1. Full write-back state
  int i, total = tcp_rpcs_get_count();
  for (i = 0; i < total; i++) {
    char hex[33];
    unsigned int ip;
    int conns;
    if (tcp_rpcs_get_secret_id_info(i, hex, &ip, &conns)) {
      char query[512];
      if (ip == 0) {
        sprintf(query, "UPDATE secrets SET bound_ip=NULL, active_conns=%d WHERE secret_hex='%s'", conns, hex);
      } else {
        char ip_str[INET_ADDRSTRLEN];
        struct in_addr addr;
        addr.s_addr = ip;
        inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
        sprintf(query, "UPDATE secrets SET bound_ip='%s', active_conns=%d WHERE secret_hex='%s'", ip_str, conns, hex);
      }
      mysql_query(conn, query);
    }
  }

  // 2. Process Kicks and Sync (Only active secrets)
  // Logic: Secrets in DB with is_active=0 should be kicked
  if (mysql_query (conn, "SELECT secret_hex FROM secrets WHERE is_active=0")) {
      kprintf ("Error: mysql_query kick check failed\n");
  } else {
      MYSQL_RES *res_kick = mysql_store_result (conn);
      if (res_kick) {
          MYSQL_ROW row_kick;
          while ((row_kick = mysql_fetch_row (res_kick))) {
              tcp_rpcs_kick_secret (row_kick[0]);
          }
          mysql_free_result (res_kick);
      }
  }

  // 3. Reload secrets
  if (mysql_query (conn, "SELECT secret_hex, bound_ip FROM secrets WHERE is_active=1")) {
    kprintf ("Error: mysql_query fetch failed\n");
    return;
  }

  MYSQL_RES *res = mysql_store_result (conn);
  if (!res) return;

  tcp_rpcs_clear_secrets ();
  MYSQL_ROW row;
  while ((row = mysql_fetch_row (res))) {
    tcp_rpcs_add_secret_from_db (row[0], row[1]);
  }
  tcp_rpcs_commit_secrets ();
  mysql_free_result (res);
}

static void *db_sync_thread_main (void *arg) {
  int tick = 0;
  while (1) {
    tick++;
    // Periodic Keepalive Check (Every 30s)
    if (tick % 3 == 0) {
        tcp_rpcs_check_keepalive();
    }
    // Periodic Full DB Sync (Every 60s)
    if (tick >= 6) {
        db_sync_secrets();
        tick = 0;
    }
    sleep (10); 
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
