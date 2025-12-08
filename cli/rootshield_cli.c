// RootShield CLI
// ========================
//
// Interactive command-line interface for RootShield.
// Author: @ImKKingshuk

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <time.h>
#include <signal.h>
#include <curl/curl.h>
#include <json-c/json.h>

// ============================================================================
// Configuration
// ============================================================================

#define API_BASE_URL "http://localhost:8080/api/v1"
#define VERSION "3.0.0"
#define REFRESH_RATE_MS 1000

// ============================================================================
// ANSI Color Codes
// ============================================================================

#define RESET       "\033[0m"
#define BOLD        "\033[1m"
#define DIM         "\033[2m"
#define ITALIC      "\033[3m"
#define UNDERLINE   "\033[4m"
#define BLINK       "\033[5m"

// Foreground colors
#define BLACK       "\033[30m"
#define RED         "\033[31m"
#define GREEN       "\033[32m"
#define YELLOW      "\033[33m"
#define BLUE        "\033[34m"
#define MAGENTA     "\033[35m"
#define CYAN        "\033[36m"
#define WHITE       "\033[37m"

// Bright foreground colors
#define BRIGHT_RED     "\033[91m"
#define BRIGHT_GREEN   "\033[92m"
#define BRIGHT_YELLOW  "\033[93m"
#define BRIGHT_BLUE    "\033[94m"
#define BRIGHT_MAGENTA "\033[95m"
#define BRIGHT_CYAN    "\033[96m"
#define BRIGHT_WHITE   "\033[97m"

// Background colors
#define BG_RED      "\033[41m"
#define BG_GREEN    "\033[42m"
#define BG_BLUE     "\033[44m"

// Cursor control
#define CLEAR_SCREEN "\033[2J"
#define CURSOR_HOME  "\033[H"
#define HIDE_CURSOR  "\033[?25l"
#define SHOW_CURSOR  "\033[?25h"
#define CLEAR_LINE   "\033[2K"

// ============================================================================
// Global State
// ============================================================================

static volatile int running = 1;
static struct termios orig_termios;
static int terminal_width = 80;
static int terminal_height = 24;

// ============================================================================
// HTTP Client
// ============================================================================

struct response_buffer {
    char *data;
    size_t size;
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct response_buffer *buf = (struct response_buffer *)userp;
    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) return 0;
    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = 0;
    return realsize;
}

static char *http_get(const char *endpoint) {
    CURL *curl;
    CURLcode res;
    struct response_buffer buf = {0};
    char url[512];
    
    snprintf(url, sizeof(url), "%s%s", API_BASE_URL, endpoint);
    buf.data = malloc(1);
    buf.size = 0;
    
    curl = curl_easy_init();
    if (!curl) { free(buf.data); return NULL; }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
    
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) { free(buf.data); return NULL; }
    return buf.data;
}

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
    if (!curl) { free(buf.data); return NULL; }
    
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    
    res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) { free(buf.data); return NULL; }
    return buf.data;
}

// ============================================================================
// Terminal Helpers
// ============================================================================

static void get_terminal_size(void) {
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0) {
        terminal_width = w.ws_col;
        terminal_height = w.ws_row;
    }
}

static void clear_screen(void) {
    printf(CLEAR_SCREEN CURSOR_HOME);
    fflush(stdout);
}

static void move_cursor(int row, int col) {
    printf("\033[%d;%dH", row, col);
}

static void print_centered(const char *text, const char *color) {
    int len = strlen(text);
    int padding = (terminal_width - len) / 2;
    if (padding > 0) printf("%*s", padding, "");
    printf("%s%s%s\n", color, text, RESET);
}

static void print_line(char c, const char *color) {
    printf("%s", color);
    for (int i = 0; i < terminal_width; i++) putchar(c);
    printf("%s\n", RESET);
}

static void disable_raw_mode(void) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
    printf(SHOW_CURSOR);
}

static void enable_raw_mode(void) {
    tcgetattr(STDIN_FILENO, &orig_termios);
    struct termios raw = orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 1;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

static int kbhit(void) {
    struct termios oldt, newt;
    int ch, oldf;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fcntl(STDIN_FILENO, F_SETFL, oldf);
    if (ch != EOF) {
        ungetc(ch, stdin);
        return 1;
    }
    return 0;
}

#include <fcntl.h>

// ============================================================================
// UI Components
// ============================================================================

static void print_banner(void) {
    const char *banner[] = {
        "",
        "  ██████╗  ██████╗  ██████╗ ████████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ ",
        "  ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗",
        "  ██████╔╝██║   ██║██║   ██║   ██║   ███████╗███████║██║█████╗  ██║     ██║  ██║",
        "  ██╔══██╗██║   ██║██║   ██║   ██║   ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║",
        "  ██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████║██║  ██║██║███████╗███████╗██████╔╝",
        "  ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ ",
        ""
    };
    
    printf("\n");
    for (int i = 0; i < 8; i++) {
        print_centered(banner[i], BRIGHT_CYAN);
    }
    print_centered("The Ultimate Shield for Rooted Devices", DIM ITALIC);
    print_centered("v" VERSION " by @ImKKingshuk", DIM);
    printf("\n");
}

static void print_box_top(const char *title) {
    printf(BRIGHT_CYAN "  ╔");
    for (int i = 0; i < 60; i++) printf("═");
    printf("╗\n");
    printf("  ║" RESET BOLD " %-58s " BRIGHT_CYAN "║\n" RESET, title);
    printf(BRIGHT_CYAN "  ╠");
    for (int i = 0; i < 60; i++) printf("═");
    printf("╣\n" RESET);
}

static void print_box_line(const char *content) {
    printf(BRIGHT_CYAN "  ║" RESET " %-58s " BRIGHT_CYAN "║\n" RESET, content);
}

static void print_box_bottom(void) {
    printf(BRIGHT_CYAN "  ╚");
    for (int i = 0; i < 60; i++) printf("═");
    printf("╝\n" RESET);
}

static void show_spinner(const char *message, int duration_ms) {
    const char *frames[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
    int num_frames = 10;
    int iterations = duration_ms / 100;
    
    printf(HIDE_CURSOR);
    for (int i = 0; i < iterations; i++) {
        printf("\r  %s%s%s %s", BRIGHT_CYAN, frames[i % num_frames], RESET, message);
        fflush(stdout);
        usleep(100000);
    }
    printf("\r" CLEAR_LINE);
    printf(SHOW_CURSOR);
}

static void print_success(const char *msg) {
    printf("  %s✓%s %s\n", BRIGHT_GREEN, RESET, msg);
}

static void print_error(const char *msg) {
    printf("  %s✗%s %s\n", BRIGHT_RED, RESET, msg);
}

static void print_warning(const char *msg) {
    printf("  %s⚠%s %s\n", BRIGHT_YELLOW, RESET, msg);
}

static void print_info(const char *msg) {
    printf("  %sℹ%s %s\n", BRIGHT_BLUE, RESET, msg);
}

// ============================================================================
// Menu System
// ============================================================================

static void print_menu_item(int num, const char *icon, const char *text, int selected) {
    if (selected) {
        printf("  %s▶%s %s%d. %s %s%s\n", BRIGHT_CYAN, RESET, BOLD, num, icon, text, RESET);
    } else {
        printf("    %s%d. %s %s%s\n", DIM, num, icon, text, RESET);
    }
}

static int show_main_menu(void) {
    clear_screen();
    print_banner();
    
    printf("\n");
    print_box_top("Main Menu");
    print_box_line("");
    print_box_line("  1. 📊  System Status          View RootShield status");
    print_box_line("  2. 🔔  Security Events        View recent security events");
    print_box_line("  3. 📋  Security Rules         Manage security rules");
    print_box_line("  4. 🔌  Plugins                View loaded plugins");
    print_box_line("  5. 📈  Statistics             Security statistics");
    print_box_line("  6. 🖥️   Live Dashboard         Real-time monitoring");
    print_box_line("");
    print_box_line("  7. ⚙️   Configuration          Configure RootShield");
    print_box_line("  8. ❓  Help                   Show help and documentation");
    print_box_line("");
    print_box_line("  0. 🚪  Exit                   Exit RootShield CLI");
    print_box_line("");
    print_box_bottom();
    
    printf("\n  %sSelect an option (0-8):%s ", BOLD, RESET);
    fflush(stdout);
    
    char input[10];
    if (fgets(input, sizeof(input), stdin)) {
        return atoi(input);
    }
    return -1;
}

// ============================================================================
// Command Implementations
// ============================================================================

static void cmd_status(void) {
    clear_screen();
    print_banner();
    
    show_spinner("Fetching system status...", 500);
    
    char *response = http_get("/status");
    
    printf("\n");
    print_box_top("System Status");
    
    if (!response) {
        print_box_line("");
        print_box_line("  ⚠️  Cannot connect to RootShield API server");
        print_box_line("");
        print_box_line("  Make sure the kernel module is loaded:");
        print_box_line("    sudo insmod rootshield.ko");
        print_box_line("");
        print_box_line("  And the API server is running:");
        print_box_line("    ./api/rootshield_api");
        print_box_line("");
    } else {
        json_object *root = json_tokener_parse(response);
        if (root) {
            json_object *status_obj, *version_obj, *uptime_obj;
            char line[64];
            
            print_box_line("");
            
            if (json_object_object_get_ex(root, "status", &status_obj)) {
                const char *status = json_object_get_string(status_obj);
                if (strcmp(status, "running") == 0) {
                    snprintf(line, sizeof(line), "  Status:     %s● RUNNING%s", BRIGHT_GREEN, RESET);
                } else {
                    snprintf(line, sizeof(line), "  Status:     %s○ STOPPED%s", BRIGHT_RED, RESET);
                }
                print_box_line(line);
            }
            
            if (json_object_object_get_ex(root, "version", &version_obj)) {
                snprintf(line, sizeof(line), "  Version:    %s", json_object_get_string(version_obj));
                print_box_line(line);
            }
            
            print_box_line("  API:        v1.0");
            print_box_line("");
            print_box_line("  Protection Features:");
            print_box_line("    ✓ Execution Monitor    ✓ File Monitor");
            print_box_line("    ✓ Process Monitor      ✓ Network Monitor");
            print_box_line("    ✓ Syscall Monitor      ✓ Memory Monitor");
            print_box_line("    ✓ Module Monitor       ✓ Anti-Rootkit");
            print_box_line("");
            
            json_object_put(root);
        }
        free(response);
    }
    
    print_box_bottom();
    
    printf("\n  Press Enter to continue...");
    getchar();
}

static void cmd_events(void) {
    clear_screen();
    print_banner();
    
    show_spinner("Fetching security events...", 500);
    
    char *response = http_get("/events");
    
    printf("\n");
    print_box_top("Recent Security Events");
    
    if (!response) {
        print_box_line("");
        print_box_line("  ⚠️  Cannot fetch events. Is the API server running?");
        print_box_line("");
    } else {
        json_object *root = json_tokener_parse(response);
        if (root && json_object_is_type(root, json_type_array)) {
            int count = json_object_array_length(root);
            
            if (count == 0) {
                print_box_line("");
                print_box_line("  ✓ No security events recorded");
                print_box_line("    Your system is secure!");
                print_box_line("");
            } else {
                char line[64];
                snprintf(line, sizeof(line), "  Showing %d most recent events:", count > 10 ? 10 : count);
                print_box_line(line);
                print_box_line("");
                
                int show = count > 10 ? 10 : count;
                for (int i = 0; i < show; i++) {
                    json_object *event = json_object_array_get_idx(root, i);
                    json_object *type_obj, *severity_obj, *pid_obj;
                    
                    json_object_object_get_ex(event, "type", &type_obj);
                    json_object_object_get_ex(event, "severity", &severity_obj);
                    json_object_object_get_ex(event, "pid", &pid_obj);
                    
                    const char *severity = severity_obj ? json_object_get_string(severity_obj) : "info";
                    const char *icon = strcmp(severity, "critical") == 0 ? "🔴" :
                                       strcmp(severity, "warning") == 0 ? "🟡" : "🔵";
                    
                    snprintf(line, sizeof(line), "  %s [%s] PID %d", icon,
                            type_obj ? json_object_get_string(type_obj) : "unknown",
                            pid_obj ? json_object_get_int(pid_obj) : 0);
                    print_box_line(line);
                }
                print_box_line("");
            }
            json_object_put(root);
        }
        free(response);
    }
    
    print_box_bottom();
    
    printf("\n  Press Enter to continue...");
    getchar();
}

static void cmd_rules(void) {
    clear_screen();
    print_banner();
    
    printf("\n");
    print_box_top("Security Rules Management");
    print_box_line("");
    print_box_line("  1. 📋  List all rules");
    print_box_line("  2. ➕  Add new rule (interactive)");
    print_box_line("  3. ❌  Delete rule");
    print_box_line("  4. ✏️   Edit rule");
    print_box_line("");
    print_box_line("  0. ⬅️   Back to main menu");
    print_box_line("");
    print_box_bottom();
    
    printf("\n  %sSelect an option:%s ", BOLD, RESET);
    
    char input[10];
    if (fgets(input, sizeof(input), stdin)) {
        int choice = atoi(input);
        
        if (choice == 1) {
            // List rules
            show_spinner("Fetching rules...", 500);
            char *response = http_get("/rules");
            
            printf("\n");
            if (response) {
                json_object *root = json_tokener_parse(response);
                if (root && json_object_is_type(root, json_type_array)) {
                    int count = json_object_array_length(root);
                    printf("  Found %d rules:\n\n", count);
                    
                    for (int i = 0; i < count; i++) {
                        json_object *rule = json_object_array_get_idx(root, i);
                        json_object *name_obj, *action_obj;
                        
                        json_object_object_get_ex(rule, "name", &name_obj);
                        json_object_object_get_ex(rule, "action", &action_obj);
                        
                        printf("  [%d] %s → %s\n", i + 1,
                               name_obj ? json_object_get_string(name_obj) : "unnamed",
                               action_obj ? json_object_get_string(action_obj) : "unknown");
                    }
                    json_object_put(root);
                } else {
                    print_info("No rules configured");
                }
                free(response);
            } else {
                print_error("Cannot fetch rules");
            }
            
            printf("\n  Press Enter to continue...");
            getchar();
        }
        else if (choice == 2) {
            // Add rule interactively
            printf("\n");
            print_info("Create New Security Rule");
            printf("\n");
            
            char name[128], action[32];
            
            printf("  %sRule name:%s ", BOLD, RESET);
            fgets(name, sizeof(name), stdin);
            name[strcspn(name, "\n")] = 0;
            
            printf("\n  %sSelect action:%s\n", BOLD, RESET);
            printf("    1. ALLOW - Allow the action\n");
            printf("    2. DENY  - Block the action\n");
            printf("    3. KILL  - Kill the process\n");
            printf("    4. ALERT - Log alert only\n");
            printf("\n  Choice: ");
            
            char action_choice[10];
            fgets(action_choice, sizeof(action_choice), stdin);
            
            switch (atoi(action_choice)) {
                case 1: strcpy(action, "allow"); break;
                case 2: strcpy(action, "deny"); break;
                case 3: strcpy(action, "kill"); break;
                case 4: strcpy(action, "alert"); break;
                default: strcpy(action, "alert");
            }
            
            // Create JSON
            char json[512];
            snprintf(json, sizeof(json),
                    "{\"name\":\"%s\",\"action\":\"%s\",\"enabled\":true,\"priority\":100}",
                    name, action);
            
            show_spinner("Creating rule...", 500);
            
            char *response = http_post("/rules", json);
            if (response) {
                print_success("Rule created successfully!");
                free(response);
            } else {
                print_error("Failed to create rule");
            }
            
            printf("\n  Press Enter to continue...");
            getchar();
        }
    }
}

static void cmd_plugins(void) {
    clear_screen();
    print_banner();
    
    show_spinner("Fetching plugins...", 500);
    
    char *response = http_get("/plugins");
    
    printf("\n");
    print_box_top("Loaded Plugins");
    
    if (!response) {
        print_box_line("");
        print_box_line("  ⚠️  Cannot fetch plugins");
        print_box_line("");
    } else {
        json_object *root = json_tokener_parse(response);
        if (root && json_object_is_type(root, json_type_array)) {
            int count = json_object_array_length(root);
            
            print_box_line("");
            
            for (int i = 0; i < count; i++) {
                json_object *plugin = json_object_array_get_idx(root, i);
                json_object *name_obj, *status_obj;
                
                json_object_object_get_ex(plugin, "name", &name_obj);
                json_object_object_get_ex(plugin, "status", &status_obj);
                
                const char *status = status_obj ? json_object_get_string(status_obj) : "unknown";
                const char *icon = strcmp(status, "active") == 0 ? "🟢" : "🔴";
                
                char line[64];
                snprintf(line, sizeof(line), "  %s %-30s [%s]", icon,
                        name_obj ? json_object_get_string(name_obj) : "unknown",
                        status);
                print_box_line(line);
            }
            
            print_box_line("");
            json_object_put(root);
        }
        free(response);
    }
    
    print_box_bottom();
    
    printf("\n  Press Enter to continue...");
    getchar();
}

static void cmd_stats(void) {
    clear_screen();
    print_banner();
    
    show_spinner("Fetching statistics...", 500);
    
    char *response = http_get("/statistics");
    
    printf("\n");
    print_box_top("Security Statistics");
    
    if (!response) {
        print_box_line("");
        print_box_line("  ⚠️  Cannot fetch statistics");
        print_box_line("");
    } else {
        json_object *root = json_tokener_parse(response);
        if (root) {
            print_box_line("");
            
            json_object_object_foreach(root, key, val) {
                char line[64];
                snprintf(line, sizeof(line), "  %-35s %8ld", key, json_object_get_int64(val));
                print_box_line(line);
            }
            
            print_box_line("");
            json_object_put(root);
        }
        free(response);
    }
    
    print_box_bottom();
    
    printf("\n  Press Enter to continue...");
    getchar();
}

static void cmd_dashboard(void) {
    clear_screen();
    printf(HIDE_CURSOR);
    
    enable_raw_mode();
    
    while (running) {
        clear_screen();
        
        // Header
        printf("\n");
        printf("  %s%s═══════════════════════════════════════════════════════════════════════════%s\n", BOLD, BRIGHT_CYAN, RESET);
        printf("  %s%s                    ROOTSHIELD LIVE DASHBOARD                              %s\n", BOLD, BRIGHT_CYAN, RESET);
        printf("  %s%s═══════════════════════════════════════════════════════════════════════════%s\n", BOLD, BRIGHT_CYAN, RESET);
        
        // Status
        char *status_resp = http_get("/status");
        printf("\n  %s[ SYSTEM STATUS ]%s\n\n", BOLD, RESET);
        
        if (status_resp) {
            json_object *root = json_tokener_parse(status_resp);
            if (root) {
                json_object *status_obj;
                if (json_object_object_get_ex(root, "status", &status_obj)) {
                    const char *status = json_object_get_string(status_obj);
                    if (strcmp(status, "running") == 0) {
                        printf("  %s●%s RootShield is %sACTIVE%s and protecting your system\n", 
                               BRIGHT_GREEN, RESET, BOLD BRIGHT_GREEN, RESET);
                    } else {
                        printf("  %s○%s RootShield is %sINACTIVE%s\n", 
                               BRIGHT_RED, RESET, BOLD BRIGHT_RED, RESET);
                    }
                }
                json_object_put(root);
            }
            free(status_resp);
        } else {
            printf("  %s○%s Cannot connect to RootShield\n", BRIGHT_RED, RESET);
        }
        
        // Stats
        char *stats_resp = http_get("/statistics");
        printf("\n  %s[ THREAT SUMMARY ]%s\n\n", BOLD, RESET);
        
        if (stats_resp) {
            json_object *root = json_tokener_parse(stats_resp);
            if (root) {
                int total_violations = 0;
                int total_blocked = 0;
                
                json_object_object_foreach(root, key, val) {
                    if (strstr(key, "violation")) total_violations += json_object_get_int(val);
                    if (strstr(key, "blocked")) total_blocked += json_object_get_int(val);
                }
                
                printf("  %s🔴 Violations Detected:%s  %d\n", BRIGHT_RED, RESET, total_violations);
                printf("  %s🟢 Threats Blocked:%s      %d\n", BRIGHT_GREEN, RESET, total_blocked);
                
                json_object_put(root);
            }
            free(stats_resp);
        }
        
        // Recent events
        printf("\n  %s[ RECENT EVENTS ]%s\n\n", BOLD, RESET);
        
        char *events_resp = http_get("/events");
        if (events_resp) {
            json_object *root = json_tokener_parse(events_resp);
            if (root && json_object_is_type(root, json_type_array)) {
                int count = json_object_array_length(root);
                int show = count > 5 ? 5 : count;
                
                if (show == 0) {
                    printf("  %s✓ No recent events%s\n", DIM, RESET);
                }
                
                for (int i = 0; i < show; i++) {
                    json_object *event = json_object_array_get_idx(root, i);
                    json_object *type_obj, *severity_obj;
                    
                    json_object_object_get_ex(event, "type", &type_obj);
                    json_object_object_get_ex(event, "severity", &severity_obj);
                    
                    const char *severity = severity_obj ? json_object_get_string(severity_obj) : "info";
                    const char *color = strcmp(severity, "critical") == 0 ? BRIGHT_RED :
                                        strcmp(severity, "warning") == 0 ? BRIGHT_YELLOW : BRIGHT_BLUE;
                    
                    printf("  %s●%s [%s]\n", color, RESET,
                           type_obj ? json_object_get_string(type_obj) : "unknown");
                }
                json_object_put(root);
            }
            free(events_resp);
        }
        
        // Footer
        printf("\n\n  %s───────────────────────────────────────────────────────────────────────────%s\n", DIM, RESET);
        time_t now = time(NULL);
        printf("  %sLast updated: %s%s", DIM, ctime(&now), RESET);
        printf("  %sPress 'q' to exit dashboard | Refreshing every %d seconds%s\n", DIM, REFRESH_RATE_MS / 1000, RESET);
        
        fflush(stdout);
        
        // Check for quit
        for (int i = 0; i < REFRESH_RATE_MS / 100; i++) {
            if (kbhit()) {
                char c = getchar();
                if (c == 'q' || c == 'Q') {
                    disable_raw_mode();
                    printf(SHOW_CURSOR);
                    return;
                }
            }
            usleep(100000);
        }
    }
    
    disable_raw_mode();
    printf(SHOW_CURSOR);
}

static void cmd_help(void) {
    clear_screen();
    print_banner();
    
    printf("\n");
    print_box_top("Help & Documentation");
    print_box_line("");
    print_box_line("  RootShield is a kernel-level security module that");
    print_box_line("  protects your rooted Android device or Linux system");
    print_box_line("  from malicious activities.");
    print_box_line("");
    print_box_line("  MONITORS:");
    print_box_line("    • Execution  - Blocks suspicious binary execution");
    print_box_line("    • File       - Protects sensitive file paths");
    print_box_line("    • Process    - Prevents code injection");
    print_box_line("    • Network    - Blocks suspicious connections");
    print_box_line("    • Syscall    - Monitors sensitive system calls");
    print_box_line("    • Memory     - Detects buffer overflows");
    print_box_line("    • Module     - Prevents rootkit loading");
    print_box_line("");
    print_box_line("  For more information:");
    print_box_line("    https://github.com/ImKKingshuk/RootShield");
    print_box_line("");
    print_box_bottom();
    
    printf("\n  Press Enter to continue...");
    getchar();
}

static void cmd_config(void) {
    clear_screen();
    print_banner();
    
    printf("\n");
    print_box_top("Configuration");
    print_box_line("");
    print_box_line("  API Server:     " API_BASE_URL);
    print_box_line("  CLI Version:    v" VERSION);
    print_box_line("  Refresh Rate:   1 second");
    print_box_line("");
    print_box_line("  Module parameters can be configured using:");
    print_box_line("    insmod rootshield.ko <parameter>=<value>");
    print_box_line("");
    print_box_line("  Available parameters:");
    print_box_line("    exec_monitor_enabled=0/1");
    print_box_line("    file_monitor_enabled=0/1");
    print_box_line("    process_monitor_enabled=0/1");
    print_box_line("    network_monitor_enabled=0/1");
    print_box_line("    verbose_logging=0/1");
    print_box_line("");
    print_box_bottom();
    
    printf("\n  Press Enter to continue...");
    getchar();
}

// ============================================================================
// Signal Handler
// ============================================================================

static void signal_handler(int sig) {
    running = 0;
    disable_raw_mode();
    printf(SHOW_CURSOR "\n");
    exit(0);
}

// ============================================================================
// Main
// ============================================================================

static void print_usage(void) {
    printf("\n");
    printf(BRIGHT_CYAN "RootShield CLI v" VERSION RESET "\n");
    printf("Usage: rootshield [options] [command]\n\n");
    printf("Commands:\n");
    printf("  status       Show system status\n");
    printf("  events       Show recent events\n");
    printf("  rules        Manage security rules\n");
    printf("  plugins      Show loaded plugins\n");
    printf("  stats        Show statistics\n");
    printf("  dashboard    Live monitoring dashboard\n");
    printf("\nOptions:\n");
    printf("  -h, --help   Show this help\n");
    printf("  -i           Start interactive mode\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    get_terminal_size();
    
    // Non-interactive command mode
    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage();
        }
        else if (strcmp(argv[1], "-i") == 0) {
            // Interactive mode - fall through
        }
        else if (strcmp(argv[1], "status") == 0) {
            cmd_status();
            curl_global_cleanup();
            return 0;
        }
        else if (strcmp(argv[1], "events") == 0) {
            cmd_events();
            curl_global_cleanup();
            return 0;
        }
        else if (strcmp(argv[1], "plugins") == 0) {
            cmd_plugins();
            curl_global_cleanup();
            return 0;
        }
        else if (strcmp(argv[1], "stats") == 0) {
            cmd_stats();
            curl_global_cleanup();
            return 0;
        }
        else if (strcmp(argv[1], "dashboard") == 0) {
            cmd_dashboard();
            curl_global_cleanup();
            return 0;
        }
        else if (strcmp(argv[1], "rules") == 0) {
            cmd_rules();
            curl_global_cleanup();
            return 0;
        }
        else {
            printf("Unknown command: %s\n", argv[1]);
            print_usage();
            curl_global_cleanup();
            return 1;
        }
    }
    
    // Interactive mode
    while (running) {
        int choice = show_main_menu();
        
        switch (choice) {
            case 1: cmd_status(); break;
            case 2: cmd_events(); break;
            case 3: cmd_rules(); break;
            case 4: cmd_plugins(); break;
            case 5: cmd_stats(); break;
            case 6: cmd_dashboard(); break;
            case 7: cmd_config(); break;
            case 8: cmd_help(); break;
            case 0:
                clear_screen();
                print_banner();
                printf("\n");
                print_centered("Thank you for using RootShield!", BRIGHT_CYAN);
                print_centered("Stay secure! 🛡️", DIM);
                printf("\n\n");
                running = 0;
                break;
            default:
                print_error("Invalid option. Please try again.");
                usleep(500000);
        }
    }
    
    curl_global_cleanup();
    return 0;
}
