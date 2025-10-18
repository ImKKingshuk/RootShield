// RootShield Plugin System Interface
// ==================================
//
// This defines the interface that all security monitor plugins must implement.
// Plugins are dynamically loadable kernel modules that can be enabled/disabled
// at runtime without recompiling the core engine.

#ifndef ROOTSHIELD_PLUGIN_H
#define ROOTSHIELD_PLUGIN_H

#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

// Plugin states
typedef enum {
    PLUGIN_STATE_UNLOADED = 0,
    PLUGIN_STATE_LOADED,
    PLUGIN_STATE_INITIALIZED,
    PLUGIN_STATE_ACTIVE,
    PLUGIN_STATE_ERROR,
    PLUGIN_STATE_DISABLED
} plugin_state_t;

// Plugin types
typedef enum {
    PLUGIN_TYPE_MONITOR = 0,
    PLUGIN_TYPE_ANALYZER,
    PLUGIN_TYPE_RESPONDER,
    PLUGIN_TYPE_INTEGRATION,
    PLUGIN_TYPE_UTILITY
} plugin_type_t;

// Plugin capabilities
#define PLUGIN_CAP_EXEC_MONITORING     (1 << 0)
#define PLUGIN_CAP_FILE_MONITORING     (1 << 1)
#define PLUGIN_CAP_PROCESS_MONITORING  (1 << 2)
#define PLUGIN_CAP_NETWORK_MONITORING  (1 << 3)
#define PLUGIN_CAP_MEMORY_MONITORING   (1 << 4)
#define PLUGIN_CAP_SYSCALL_MONITORING  (1 << 5)
#define PLUGIN_CAP_MODULE_MONITORING   (1 << 6)
#define PLUGIN_CAP_BEHAVIORAL_ANALYSIS (1 << 7)
#define PLUGIN_CAP_ANOMALY_DETECTION   (1 << 8)
#define PLUGIN_CAP_ROOTKIT_DETECTION   (1 << 9)
#define PLUGIN_CAP_FORENSICS          (1 << 10)

// Plugin metadata structure
struct plugin_metadata {
    const char *name;
    const char *version;
    const char *description;
    const char *author;
    plugin_type_t type;
    uint32_t capabilities;
    const char *dependencies[16];  // Maximum 16 dependencies
    uint32_t api_version;
};

// Plugin operations structure
struct plugin_operations {
    // Lifecycle operations
    int (*init)(void *plugin_data);
    void (*exit)(void *plugin_data);
    int (*start)(void *plugin_data);
    void (*stop)(void *plugin_data);

    // Configuration operations
    int (*configure)(void *plugin_data, const char *key, const char *value);
    int (*get_config)(void *plugin_data, const char *key, char *value, size_t size);

    // Event handling
    int (*handle_event)(void *plugin_data, struct security_event *event);
    int (*process_data)(void *plugin_data, void *data, size_t size);

    // Health and statistics
    int (*get_stats)(void *plugin_data, struct plugin_stats *stats);
    int (*health_check)(void *plugin_data);

    // Plugin-specific operations (can be extended)
    void *private_ops;
};

// Plugin statistics
struct plugin_stats {
    uint64_t events_processed;
    uint64_t alerts_generated;
    uint64_t blocks_performed;
    uint64_t errors_encountered;
    uint64_t uptime_seconds;
    uint32_t memory_usage_kb;
};

// Security event structure
struct security_event {
    uint64_t timestamp;
    uint32_t event_id;
    uint32_t severity;
    const char *source_plugin;
    const char *event_type;
    void *event_data;
    size_t data_size;
    uint32_t pid;
    uint32_t uid;
    char process_name[64];
    char path[256];
};

// Main plugin structure
struct rootshield_plugin {
    struct plugin_metadata metadata;
    struct plugin_operations *ops;
    plugin_state_t state;
    void *private_data;
    struct kobject kobj;  // For sysfs integration
    struct list_head list; // For plugin registry
    spinlock_t lock;
    atomic_t ref_count;
};

// Plugin registration functions
extern int register_plugin(struct rootshield_plugin *plugin);
extern void unregister_plugin(struct rootshield_plugin *plugin);

// Plugin management functions
extern struct rootshield_plugin *find_plugin(const char *name);
extern int load_plugin(const char *name);
extern int unload_plugin(const char *name);
extern int enable_plugin(const char *name);
extern int disable_plugin(const char *name);

// Plugin communication
extern int send_event_to_plugin(struct rootshield_plugin *plugin, struct security_event *event);
extern int broadcast_event(struct security_event *event, uint32_t target_capabilities);

// Plugin dependency management
extern int check_dependencies(struct rootshield_plugin *plugin);
extern int resolve_dependencies(struct rootshield_plugin *plugin);

// Plugin versioning
#define PLUGIN_API_VERSION_MAJOR 1
#define PLUGIN_API_VERSION_MINOR 0
#define PLUGIN_API_VERSION ((PLUGIN_API_VERSION_MAJOR << 16) | PLUGIN_API_VERSION_MINOR)

#endif /* ROOTSHIELD_PLUGIN_H */
