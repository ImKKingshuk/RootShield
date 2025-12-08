// RootShield CLI Tool
// ====================
//
// Command-line interface for managing and monitoring RootShield.
// Communicates with the API server via HTTP.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <json-c/json.h>

#define API_BASE_URL "http://localhost:8080/api/v1"
#define VERSION "3.0.0"

// Response buffer for HTTP requests
struct response_buffer {
    char *data;
    size_t size;
};

// CURL write callback
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct response_buffer *buf = (struct response_buffer *)userp;

    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) {
        fprintf(stderr, "Error: Out of memory\n");
        return 0;
    }

    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = 0;

    return realsize;
}

// HTTP GET request
static char *http_get(const char *endpoint) {
    CURL *curl;
    CURLcode res;
    struct response_buffer buf = {0};
    char url[512];

    snprintf(url, sizeof(url), "%s%s", API_BASE_URL, endpoint);

    buf.data = malloc(1);
    buf.size = 0;

    curl = curl_easy_init();
    if (!curl) {
        free(buf.data);
        return NULL;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "Error: %s\n", curl_easy_strerror(res));
        free(buf.data);
        return NULL;
    }

    return buf.data;
}

// HTTP POST request
static char *http_post(const char *endpoint, const char *json_data) {
    CURL *curl;
    CURLcode res;
    struct response_buffer buf = {0};
    struct curl_slist *headers = NULL;
    char url[512];

    snprintf(url, sizeof(url), "%s%s", API_BASE_URL, endpoint);

    buf.data = malloc(1);
    buf.size = 0;

    curl = curl_easy_init();
    if (!curl) {
        free(buf.data);
        return NULL;
    }

    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "Error: %s\n", curl_easy_strerror(res));
        free(buf.data);
        return NULL;
    }

    return buf.data;
}

// Print colored output
static void print_color(const char *color, const char *text) {
    printf("%s%s\033[0m", color, text);
}

static void print_success(const char *text) { print_color("\033[1;32m", text); }
static void print_warning(const char *text) { print_color("\033[1;33m", text); }
static void print_error(const char *text) { print_color("\033[1;31m", text); }
static void print_info(const char *text) { print_color("\033[1;34m", text); }

// Command: status
static int cmd_status(void) {
    char *response = http_get("/status");
    if (!response) {
        print_error("Failed to connect to RootShield API server\n");
        printf("Make sure the API server is running: ./api/rootshield_api\n");
        return 1;
    }

    json_object *root = json_tokener_parse(response);
    if (!root) {
        print_error("Invalid JSON response\n");
        free(response);
        return 1;
    }

    json_object *status_obj, *version_obj, *api_version_obj;

    printf("\n");
    print_info("╔══════════════════════════════════════╗\n");
    print_info("║         RootShield Status            ║\n");
    print_info("╚══════════════════════════════════════╝\n");
    printf("\n");

    if (json_object_object_get_ex(root, "status", &status_obj)) {
        const char *status = json_object_get_string(status_obj);
        printf("  Status:      ");
        if (strcmp(status, "running") == 0) {
            print_success("● RUNNING\n");
        } else {
            print_error("○ STOPPED\n");
        }
    }

    if (json_object_object_get_ex(root, "version", &version_obj)) {
        printf("  Version:     %s\n", json_object_get_string(version_obj));
    }

    if (json_object_object_get_ex(root, "api_version", &api_version_obj)) {
        printf("  API Version: %s\n", json_object_get_string(api_version_obj));
    }

    printf("\n");

    json_object_put(root);
    free(response);
    return 0;
}

// Command: events
static int cmd_events(int limit) {
    char *response = http_get("/events");
    if (!response) {
        print_error("Failed to fetch events\n");
        return 1;
    }

    json_object *root = json_tokener_parse(response);
    if (!root || !json_object_is_type(root, json_type_array)) {
        print_error("Invalid JSON response\n");
        free(response);
        return 1;
    }

    int count = json_object_array_length(root);
    if (count == 0) {
        printf("No security events recorded.\n");
        json_object_put(root);
        free(response);
        return 0;
    }

    printf("\n");
    print_info("Recent Security Events:\n");
    printf("─────────────────────────────────────────────────────────────────────\n");

    int show = (limit > 0 && limit < count) ? limit : count;
    for (int i = 0; i < show; i++) {
        json_object *event = json_object_array_get_idx(root, i);
        json_object *type_obj, *severity_obj, *message_obj, *pid_obj, *timestamp_obj;

        json_object_object_get_ex(event, "type", &type_obj);
        json_object_object_get_ex(event, "severity", &severity_obj);
        json_object_object_get_ex(event, "message", &message_obj);
        json_object_object_get_ex(event, "pid", &pid_obj);
        json_object_object_get_ex(event, "timestamp", &timestamp_obj);

        const char *severity = severity_obj ? json_object_get_string(severity_obj) : "info";

        // Severity indicator
        if (strcmp(severity, "critical") == 0) {
            print_error("● ");
        } else if (strcmp(severity, "warning") == 0) {
            print_warning("● ");
        } else {
            print_info("● ");
        }

        printf("[%s] ", type_obj ? json_object_get_string(type_obj) : "unknown");
        printf("PID %d: ", pid_obj ? json_object_get_int(pid_obj) : 0);
        printf("%s\n", message_obj ? json_object_get_string(message_obj) : "");
    }

    printf("─────────────────────────────────────────────────────────────────────\n");
    printf("Showing %d of %d events\n\n", show, count);

    json_object_put(root);
    free(response);
    return 0;
}

// Command: rules list
static int cmd_rules_list(void) {
    char *response = http_get("/rules");
    if (!response) {
        print_error("Failed to fetch rules\n");
        return 1;
    }

    json_object *root = json_tokener_parse(response);
    if (!root || !json_object_is_type(root, json_type_array)) {
        print_error("Invalid JSON response\n");
        free(response);
        return 1;
    }

    int count = json_object_array_length(root);
    printf("\n");
    print_info("Security Rules:\n");
    printf("─────────────────────────────────────────────────────────────────────\n");

    if (count == 0) {
        printf("  No rules configured.\n");
    } else {
        printf("  %-4s %-20s %-10s %-8s %s\n", "ID", "Name", "Action", "Priority", "Enabled");
        printf("  %-4s %-20s %-10s %-8s %s\n", "──", "────", "──────", "────────", "───────");

        for (int i = 0; i < count; i++) {
            json_object *rule = json_object_array_get_idx(root, i);
            json_object *id_obj, *name_obj, *action_obj, *priority_obj, *enabled_obj;

            json_object_object_get_ex(rule, "id", &id_obj);
            json_object_object_get_ex(rule, "name", &name_obj);
            json_object_object_get_ex(rule, "action", &action_obj);
            json_object_object_get_ex(rule, "priority", &priority_obj);
            json_object_object_get_ex(rule, "enabled", &enabled_obj);

            printf("  %-4d %-20s %-10s %-8d %s\n",
                   id_obj ? json_object_get_int(id_obj) : 0,
                   name_obj ? json_object_get_string(name_obj) : "",
                   action_obj ? json_object_get_string(action_obj) : "",
                   priority_obj ? json_object_get_int(priority_obj) : 0,
                   (enabled_obj && json_object_get_boolean(enabled_obj)) ? "Yes" : "No");
        }
    }

    printf("─────────────────────────────────────────────────────────────────────\n");
    printf("Total: %d rules\n\n", count);

    json_object_put(root);
    free(response);
    return 0;
}

// Command: rules add
static int cmd_rules_add(const char *json_str) {
    if (!json_str) {
        print_error("Usage: rootshield_cli rules add '<json>'\n");
        return 1;
    }

    // Validate JSON
    json_object *test = json_tokener_parse(json_str);
    if (!test) {
        print_error("Invalid JSON\n");
        return 1;
    }
    json_object_put(test);

    char *response = http_post("/rules", json_str);
    if (!response) {
        print_error("Failed to create rule\n");
        return 1;
    }

    json_object *root = json_tokener_parse(response);
    if (root) {
        json_object *status_obj;
        if (json_object_object_get_ex(root, "status", &status_obj)) {
            if (strcmp(json_object_get_string(status_obj), "success") == 0) {
                print_success("Rule created successfully\n");
            }
        }
        json_object_put(root);
    }

    free(response);
    return 0;
}

// Command: plugins
static int cmd_plugins(void) {
    char *response = http_get("/plugins");
    if (!response) {
        print_error("Failed to fetch plugins\n");
        return 1;
    }

    json_object *root = json_tokener_parse(response);
    if (!root || !json_object_is_type(root, json_type_array)) {
        print_error("Invalid JSON response\n");
        free(response);
        return 1;
    }

    int count = json_object_array_length(root);
    printf("\n");
    print_info("Loaded Plugins:\n");
    printf("─────────────────────────────────────────────────────────────────────\n");

    for (int i = 0; i < count; i++) {
        json_object *plugin = json_object_array_get_idx(root, i);
        json_object *name_obj, *version_obj, *status_obj;

        json_object_object_get_ex(plugin, "name", &name_obj);
        json_object_object_get_ex(plugin, "version", &version_obj);
        json_object_object_get_ex(plugin, "status", &status_obj);

        const char *status = status_obj ? json_object_get_string(status_obj) : "unknown";

        printf("  ");
        if (strcmp(status, "active") == 0) {
            print_success("● ");
        } else {
            print_warning("○ ");
        }
        printf("%-20s v%-8s [%s]\n",
               name_obj ? json_object_get_string(name_obj) : "unknown",
               version_obj ? json_object_get_string(version_obj) : "?",
               status);
    }

    printf("─────────────────────────────────────────────────────────────────────\n");
    printf("Total: %d plugins\n\n", count);

    json_object_put(root);
    free(response);
    return 0;
}

// Command: stats
static int cmd_stats(void) {
    char *response = http_get("/statistics");
    if (!response) {
        print_error("Failed to fetch statistics\n");
        return 1;
    }

    json_object *root = json_tokener_parse(response);
    if (!root) {
        print_error("Invalid JSON response\n");
        free(response);
        return 1;
    }

    printf("\n");
    print_info("╔══════════════════════════════════════╗\n");
    print_info("║       Security Statistics            ║\n");
    print_info("╚══════════════════════════════════════╝\n");
    printf("\n");

    json_object_object_foreach(root, key, val) {
        printf("  %-30s %ld\n", key, json_object_get_int64(val));
    }

    printf("\n");

    json_object_put(root);
    free(response);
    return 0;
}

// Print usage
static void print_usage(void) {
    printf("\n");
    print_info("RootShield CLI v%s\n", VERSION);
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
    printf("Usage: rootshield_cli <command> [options]\n\n");
    printf("Commands:\n");
    printf("  status              Show system status\n");
    printf("  events [limit]      Show recent security events\n");
    printf("  rules list          List all security rules\n");
    printf("  rules add '<json>'  Add a new security rule\n");
    printf("  plugins             List loaded plugins\n");
    printf("  stats               Show security statistics\n");
    printf("  help                Show this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  rootshield_cli status\n");
    printf("  rootshield_cli events 10\n");
    printf("  rootshield_cli rules add '{\"name\":\"block_su\",\"action\":\"kill\",\"conditions\":\"{}\"}'\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);

    int ret = 0;
    const char *cmd = argv[1];

    if (strcmp(cmd, "status") == 0) {
        ret = cmd_status();
    } else if (strcmp(cmd, "events") == 0) {
        int limit = (argc > 2) ? atoi(argv[2]) : 0;
        ret = cmd_events(limit);
    } else if (strcmp(cmd, "rules") == 0) {
        if (argc < 3) {
            printf("Usage: rootshield_cli rules <list|add>\n");
            ret = 1;
        } else if (strcmp(argv[2], "list") == 0) {
            ret = cmd_rules_list();
        } else if (strcmp(argv[2], "add") == 0 && argc > 3) {
            ret = cmd_rules_add(argv[3]);
        } else {
            printf("Usage: rootshield_cli rules <list|add>\n");
            ret = 1;
        }
    } else if (strcmp(cmd, "plugins") == 0) {
        ret = cmd_plugins();
    } else if (strcmp(cmd, "stats") == 0) {
        ret = cmd_stats();
    } else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        print_usage();
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        print_usage();
        ret = 1;
    }

    curl_global_cleanup();
    return ret;
}
