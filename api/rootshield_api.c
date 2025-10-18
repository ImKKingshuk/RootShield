// RootShield REST API Server
// ===========================
//
// RESTful API server for remote management, monitoring, and configuration
// of the RootShield security system.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <microhttpd.h>
#include <json-c/json.h>
#include <sqlite3.h>

// API Configuration
#define API_PORT 8080
#define API_HOST "127.0.0.1"
#define DATABASE_PATH "/var/lib/rootshield/rootshield.db"
#define MAX_CONNECTIONS 100
#define API_VERSION "v1"

// Database schema
#define CREATE_TABLES_SQL \
    "CREATE TABLE IF NOT EXISTS events (" \
    "    id INTEGER PRIMARY KEY AUTOINCREMENT," \
    "    timestamp INTEGER NOT NULL," \
    "    type TEXT NOT NULL," \
    "    severity TEXT NOT NULL," \
    "    source TEXT NOT NULL," \
    "    pid INTEGER," \
    "    uid INTEGER," \
    "    comm TEXT," \
    "    path TEXT," \
    "    message TEXT," \
    "    data TEXT" \
    ");" \
    "CREATE TABLE IF NOT EXISTS rules (" \
    "    id INTEGER PRIMARY KEY AUTOINCREMENT," \
    "    name TEXT UNIQUE NOT NULL," \
    "    description TEXT," \
    "    action TEXT NOT NULL," \
    "    conditions TEXT," \
    "    priority INTEGER DEFAULT 0," \
    "    enabled INTEGER DEFAULT 1," \
    "    created_at INTEGER," \
    "    updated_at INTEGER" \
    ");" \
    "CREATE TABLE IF NOT EXISTS plugins (" \
    "    id INTEGER PRIMARY KEY AUTOINCREMENT," \
    "    name TEXT UNIQUE NOT NULL," \
    "    version TEXT," \
    "    status TEXT," \
    "    capabilities TEXT," \
    "    config TEXT," \
    "    loaded_at INTEGER" \
    ");" \
    "CREATE TABLE IF NOT EXISTS statistics (" \
    "    id INTEGER PRIMARY KEY AUTOINCREMENT," \
    "    timestamp INTEGER NOT NULL," \
    "    component TEXT NOT NULL," \
    "    metric TEXT NOT NULL," \
    "    value INTEGER NOT NULL" \
    ");"

// API Server structure
struct api_server {
    struct MHD_Daemon *daemon;
    sqlite3 *db;
    pthread_mutex_t db_mutex;
    char *host;
    int port;
    int max_connections;
};

// Global server instance
static struct api_server *g_server = NULL;

// Database functions
static int init_database(sqlite3 **db)
{
    int rc = sqlite3_open(DATABASE_PATH, db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(*db));
        return -1;
    }

    // Create tables
    rc = sqlite3_exec(*db, CREATE_TABLES_SQL, 0, 0, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to create tables: %s\n", sqlite3_errmsg(*db));
        sqlite3_close(*db);
        return -1;
    }

    return 0;
}

static int store_event(sqlite3 *db, const char *type, const char *severity,
                      const char *source, int pid, int uid, const char *comm,
                      const char *path, const char *message, const char *data)
{
    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO events (timestamp, type, severity, source, "
                     "pid, uid, comm, path, message, data) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, time(NULL));
    sqlite3_bind_text(stmt, 2, type, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, severity, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, source, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, pid);
    sqlite3_bind_int(stmt, 6, uid);
    sqlite3_bind_text(stmt, 7, comm, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 9, message, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 10, data, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

// HTTP request handlers
static int handle_status(struct MHD_Connection *connection)
{
    json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_string("running"));
    json_object_object_add(response, "version", json_object_new_string("3.0.0"));
    json_object_object_add(response, "api_version", json_object_new_string(API_VERSION));

    const char *json_str = json_object_to_json_string(response);
    struct MHD_Response *mhd_response = MHD_create_response_from_buffer(
        strlen(json_str), (void *)json_str, MHD_RESPMEM_MUST_COPY);

    MHD_add_response_header(mhd_response, "Content-Type", "application/json");
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, mhd_response);
    MHD_destroy_response(mhd_response);
    json_object_put(response);

    return ret;
}

static int handle_events(struct MHD_Connection *connection, const char *method,
                        const char *upload_data, size_t *upload_data_size)
{
    if (strcmp(method, "GET") == 0) {
        // Get recent events
        json_object *response = json_object_new_array();

        // Query database for recent events
        sqlite3_stmt *stmt;
        const char *sql = "SELECT id, timestamp, type, severity, source, pid, "
                         "uid, comm, path, message FROM events "
                         "ORDER BY timestamp DESC LIMIT 100";

        pthread_mutex_lock(&g_server->db_mutex);
        int rc = sqlite3_prepare_v2(g_server->db, sql, -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                json_object *event = json_object_new_object();
                json_object_object_add(event, "id",
                    json_object_new_int(sqlite3_column_int(stmt, 0)));
                json_object_object_add(event, "timestamp",
                    json_object_new_int64(sqlite3_column_int64(stmt, 1)));
                json_object_object_add(event, "type",
                    json_object_new_string((const char *)sqlite3_column_text(stmt, 2)));
                json_object_object_add(event, "severity",
                    json_object_new_string((const char *)sqlite3_column_text(stmt, 3)));
                json_object_object_add(event, "source",
                    json_object_new_string((const char *)sqlite3_column_text(stmt, 4)));
                json_object_object_add(event, "pid",
                    json_object_new_int(sqlite3_column_int(stmt, 5)));
                json_object_object_add(event, "uid",
                    json_object_new_int(sqlite3_column_int(stmt, 6)));
                json_object_object_add(event, "comm",
                    json_object_new_string((const char *)sqlite3_column_text(stmt, 7)));
                json_object_object_add(event, "path",
                    json_object_new_string((const char *)sqlite3_column_text(stmt, 8)));
                json_object_object_add(event, "message",
                    json_object_new_string((const char *)sqlite3_column_text(stmt, 9)));

                json_object_array_add(response, event);
            }
            sqlite3_finalize(stmt);
        }
        pthread_mutex_unlock(&g_server->db_mutex);

        const char *json_str = json_object_to_json_string(response);
        struct MHD_Response *mhd_response = MHD_create_response_from_buffer(
            strlen(json_str), (void *)json_str, MHD_RESPMEM_MUST_COPY);

        MHD_add_response_header(mhd_response, "Content-Type", "application/json");
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, mhd_response);
        MHD_destroy_response(mhd_response);
        json_object_put(response);

        return ret;
    }

    return MHD_NO;
}

static int handle_rules(struct MHD_Connection *connection, const char *method,
                       const char *upload_data, size_t *upload_data_size)
{
    if (strcmp(method, "GET") == 0) {
        // Get all rules
        json_object *response = json_object_new_array();

        sqlite3_stmt *stmt;
        const char *sql = "SELECT id, name, description, action, conditions, "
                         "priority, enabled FROM rules";

        pthread_mutex_lock(&g_server->db_mutex);
        int rc = sqlite3_prepare_v2(g_server->db, sql, -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                json_object *rule = json_object_new_object();
                json_object_object_add(rule, "id",
                    json_object_new_int(sqlite3_column_int(stmt, 0)));
                json_object_object_add(rule, "name",
                    json_object_new_string((const char *)sqlite3_column_text(stmt, 1)));
                json_object_object_add(rule, "description",
                    json_object_new_string((const char *)sqlite3_column_text(stmt, 2)));
                json_object_object_add(rule, "action",
                    json_object_new_string((const char *)sqlite3_column_text(stmt, 3)));
                json_object_object_add(rule, "conditions",
                    json_object_new_string((const char *)sqlite3_column_text(stmt, 4)));
                json_object_object_add(rule, "priority",
                    json_object_new_int(sqlite3_column_int(stmt, 5)));
                json_object_object_add(rule, "enabled",
                    json_object_new_boolean(sqlite3_column_int(stmt, 6)));

                json_object_array_add(response, rule);
            }
            sqlite3_finalize(stmt);
        }
        pthread_mutex_unlock(&g_server->db_mutex);

        const char *json_str = json_object_to_json_string(response);
        struct MHD_Response *mhd_response = MHD_create_response_from_buffer(
            strlen(json_str), (void *)json_str, MHD_RESPMEM_MUST_COPY);

        MHD_add_response_header(mhd_response, "Content-Type", "application/json");
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, mhd_response);
        MHD_destroy_response(mhd_response);
        json_object_put(response);

        return ret;
    } else if (strcmp(method, "POST") == 0) {
        // Create new rule
        // Parse JSON from upload_data
        json_object *request = json_tokener_parse(upload_data);
        if (request) {
            json_object *name_obj, *action_obj, *conditions_obj;

            if (json_object_object_get_ex(request, "name", &name_obj) &&
                json_object_object_get_ex(request, "action", &action_obj) &&
                json_object_object_get_ex(request, "conditions", &conditions_obj)) {

                const char *name = json_object_get_string(name_obj);
                const char *action = json_object_get_string(action_obj);
                const char *conditions = json_object_get_string(conditions_obj);

                // Insert into database
                sqlite3_stmt *stmt;
                const char *sql = "INSERT INTO rules (name, action, conditions, "
                                 "created_at) VALUES (?, ?, ?, ?)";

                pthread_mutex_lock(&g_server->db_mutex);
                int rc = sqlite3_prepare_v2(g_server->db, sql, -1, &stmt, NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
                    sqlite3_bind_text(stmt, 2, action, -1, SQLITE_STATIC);
                    sqlite3_bind_text(stmt, 3, conditions, -1, SQLITE_STATIC);
                    sqlite3_bind_int64(stmt, 4, time(NULL));

                    rc = sqlite3_step(stmt);
                    sqlite3_finalize(stmt);

                    if (rc == SQLITE_DONE) {
                        json_object *response = json_object_new_object();
                        json_object_object_add(response, "status",
                            json_object_new_string("success"));
                        json_object_object_add(response, "message",
                            json_object_new_string("Rule created successfully"));

                        const char *json_str = json_object_to_json_string(response);
                        struct MHD_Response *mhd_response = MHD_create_response_from_buffer(
                            strlen(json_str), (void *)json_str, MHD_RESPMEM_MUST_COPY);

                        MHD_add_response_header(mhd_response, "Content-Type", "application/json");
                        int ret = MHD_queue_response(connection, MHD_HTTP_CREATED, mhd_response);
                        MHD_destroy_response(mhd_response);
                        json_object_put(response);

                        pthread_mutex_unlock(&g_server->db_mutex);
                        json_object_put(request);
                        return ret;
                    }
                }
                pthread_mutex_unlock(&g_server->db_mutex);
            }
            json_object_put(request);
        }
    }

    return MHD_NO;
}

static int handle_plugins(struct MHD_Connection *connection, const char *method)
{
    if (strcmp(method, "GET") == 0) {
        // Get plugin status
        json_object *response = json_object_new_array();

        // This would query the kernel module for plugin status
        // For now, return mock data
        json_object *plugin = json_object_new_object();
        json_object_object_add(plugin, "name", json_object_new_string("exec_monitor"));
        json_object_object_add(plugin, "status", json_object_new_string("active"));
        json_object_object_add(plugin, "version", json_object_new_string("1.0.0"));
        json_object_array_add(response, plugin);

        const char *json_str = json_object_to_json_string(response);
        struct MHD_Response *mhd_response = MHD_create_response_from_buffer(
            strlen(json_str), (void *)json_str, MHD_RESPMEM_MUST_COPY);

        MHD_add_response_header(mhd_response, "Content-Type", "application/json");
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, mhd_response);
        MHD_destroy_response(mhd_response);
        json_object_put(response);

        return ret;
    }

    return MHD_NO;
}

static int handle_statistics(struct MHD_Connection *connection)
{
    json_object *response = json_object_new_object();

    // Get statistics from database
    sqlite3_stmt *stmt;
    const char *sql = "SELECT component, metric, value FROM statistics "
                     "WHERE timestamp > ? ORDER BY timestamp DESC";

    pthread_mutex_lock(&g_server->db_mutex);
    int rc = sqlite3_prepare_v2(g_server->db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, time(NULL) - 3600); // Last hour

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *component = (const char *)sqlite3_column_text(stmt, 0);
            const char *metric = (const char *)sqlite3_column_text(stmt, 1);
            int value = sqlite3_column_int(stmt, 2);

            char key[256];
            snprintf(key, sizeof(key), "%s_%s", component, metric);
            json_object_object_add(response, key, json_object_new_int(value));
        }
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&g_server->db_mutex);

    const char *json_str = json_object_to_json_string(response);
    struct MHD_Response *mhd_response = MHD_create_response_from_buffer(
        strlen(json_str), (void *)json_str, MHD_RESPMEM_MUST_COPY);

    MHD_add_response_header(mhd_response, "Content-Type", "application/json");
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, mhd_response);
    MHD_destroy_response(mhd_response);
    json_object_put(response);

    return ret;
}

// Main request handler
static int request_handler(void *cls, struct MHD_Connection *connection,
                          const char *url, const char *method,
                          const char *version, const char *upload_data,
                          size_t *upload_data_size, void **con_cls)
{
    (void)cls; (void)version; (void)con_cls;

    if (strcmp(url, "/api/v1/status") == 0) {
        return handle_status(connection);
    } else if (strcmp(url, "/api/v1/events") == 0) {
        return handle_events(connection, method, upload_data, upload_data_size);
    } else if (strcmp(url, "/api/v1/rules") == 0) {
        return handle_rules(connection, method, upload_data, upload_data_size);
    } else if (strcmp(url, "/api/v1/plugins") == 0) {
        return handle_plugins(connection, method);
    } else if (strcmp(url, "/api/v1/statistics") == 0) {
        return handle_statistics(connection);
    } else {
        // 404 Not Found
        const char *not_found = "{\"error\": \"Not Found\"}";
        struct MHD_Response *response = MHD_create_response_from_buffer(
            strlen(not_found), (void *)not_found, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(response, "Content-Type", "application/json");
        int ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
        MHD_destroy_response(response);
        return ret;
    }

    return MHD_NO;
}

static struct api_server *create_api_server(const char *host, int port, int max_connections)
{
    struct api_server *server = calloc(1, sizeof(struct api_server));
    if (!server) {
        perror("Failed to allocate server");
        return NULL;
    }

    server->host = strdup(host);
    server->port = port;
    server->max_connections = max_connections;
    pthread_mutex_init(&server->db_mutex, NULL);

    // Initialize database
    if (init_database(&server->db) != 0) {
        free(server->host);
        free(server);
        return NULL;
    }

    // Start MHD daemon
    server->daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, port,
                                     NULL, NULL,
                                     &request_handler, NULL,
                                     MHD_OPTION_CONNECTION_LIMIT, max_connections,
                                     MHD_OPTION_CONNECTION_TIMEOUT, 30,
                                     MHD_OPTION_END);

    if (!server->daemon) {
        fprintf(stderr, "Failed to start HTTP daemon\n");
        sqlite3_close(server->db);
        free(server->host);
        free(server);
        return NULL;
    }

    return server;
}

static void destroy_api_server(struct api_server *server)
{
    if (server) {
        if (server->daemon) {
            MHD_stop_daemon(server->daemon);
        }
        if (server->db) {
            sqlite3_close(server->db);
        }
        pthread_mutex_destroy(&server->db_mutex);
        free(server->host);
        free(server);
    }
}

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;

    printf("RootShield API Server v3.0.0 starting...\n");

    g_server = create_api_server(API_HOST, API_PORT, MAX_CONNECTIONS);
    if (!g_server) {
        fprintf(stderr, "Failed to create API server\n");
        return EXIT_FAILURE;
    }

    printf("API server listening on http://%s:%d\n", API_HOST, API_PORT);
    printf("Press Ctrl+C to stop\n");

    // Wait for termination signal
    pause();

    printf("Shutting down API server...\n");
    destroy_api_server(g_server);

    return EXIT_SUCCESS;
}
