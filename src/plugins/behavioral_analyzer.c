// RootShield Behavioral Analysis Plugin
// ======================================
//
// Advanced behavioral analysis using statistical models to detect anomalous
// system behavior that might indicate compromise or attack.

#include "../include/plugin.h"
#include "../include/events.h"
#include "../include/rootshield.h"

#define BEHAVIORAL_PLUGIN_NAME "behavioral_analyzer"
#define BEHAVIORAL_PLUGIN_VERSION "1.0.0"
#define BEHAVIORAL_PLUGIN_DESCRIPTION "Behavioral analysis and anomaly detection"

// Analysis windows
#define ANALYSIS_WINDOW_SHORT  60   // 1 minute
#define ANALYSIS_WINDOW_MEDIUM 300  // 5 minutes
#define ANALYSIS_WINDOW_LONG   3600 // 1 hour

// Anomaly thresholds
#define ANOMALY_THRESHOLD_LOW    2.0
#define ANOMALY_THRESHOLD_MEDIUM 3.0
#define ANOMALY_THRESHOLD_HIGH   5.0

// Behavioral features
typedef enum {
    FEATURE_SYSCALL_FREQUENCY = 0,
    FEATURE_PROCESS_SPAWN_RATE,
    FEATURE_FILE_ACCESS_PATTERNS,
    FEATURE_NETWORK_CONNECTIONS,
    FEATURE_MEMORY_USAGE,
    FEATURE_CPU_USAGE,
    FEATURE_IO_OPERATIONS,
    FEATURE_EXECUTION_PATTERNS,
    FEATURE_MAX
} behavioral_feature_t;

// Statistical model for anomaly detection
struct statistical_model {
    behavioral_feature_t feature;
    char name[32];

    // Historical data (sliding window)
    uint64_t *values;
    size_t window_size;
    size_t current_index;
    bool initialized;

    // Statistical measures
    double mean;
    double variance;
    double std_dev;
    uint64_t min_value;
    uint64_t max_value;

    // Anomaly detection
    double threshold_multiplier;
    uint32_t consecutive_anomalies;
    uint32_t anomaly_count;
};

// Process behavioral profile
struct process_profile {
    pid_t pid;
    char comm[16];
    uid_t uid;

    // Feature models
    struct statistical_model models[FEATURE_MAX];

    // Behavioral score
    double anomaly_score;
    uint32_t flags;

    // Metadata
    uint64_t first_seen;
    uint64_t last_seen;
    uint64_t event_count;

    struct rb_node node; // For efficient lookup
};

// Plugin private data
struct behavioral_data {
    // Process profiles (red-black tree for fast lookup)
    struct rb_root process_tree;
    spinlock_t tree_lock;

    // Global statistical models
    struct statistical_model global_models[FEATURE_MAX];

    // Configuration
    uint32_t analysis_window_seconds;
    double anomaly_threshold;
    bool adaptive_thresholds;
    uint32_t max_profiles;

    // Statistics
    atomic_t profiles_active;
    atomic_t anomalies_detected;
    atomic_t false_positives;

    // Workqueue for analysis
    struct workqueue_struct *analysis_workqueue;
    struct delayed_work analysis_work;
};

// Feature names
static const char *feature_names[FEATURE_MAX] = {
    [FEATURE_SYSCALL_FREQUENCY] = "syscall_frequency",
    [FEATURE_PROCESS_SPAWN_RATE] = "process_spawn_rate",
    [FEATURE_FILE_ACCESS_PATTERNS] = "file_access_patterns",
    [FEATURE_NETWORK_CONNECTIONS] = "network_connections",
    [FEATURE_MEMORY_USAGE] = "memory_usage",
    [FEATURE_CPU_USAGE] = "cpu_usage",
    [FEATURE_IO_OPERATIONS] = "io_operations",
    [FEATURE_EXECUTION_PATTERNS] = "execution_patterns"
};

// Plugin metadata
static struct plugin_metadata behavioral_metadata = {
    .name = BEHAVIORAL_PLUGIN_NAME,
    .version = BEHAVIORAL_PLUGIN_VERSION,
    .description = BEHAVIORAL_PLUGIN_DESCRIPTION,
    .author = "@ImKKingshuk",
    .type = PLUGIN_TYPE_ANALYZER,
    .capabilities = PLUGIN_CAP_BEHAVIORAL_ANALYSIS | PLUGIN_CAP_ANOMALY_DETECTION,
    .dependencies = {"core_engine", "event_system", NULL},
    .api_version = PLUGIN_API_VERSION
};

// Plugin operations
static struct plugin_operations behavioral_ops = {
    .init = behavioral_init,
    .exit = behavioral_exit,
    .start = behavioral_start,
    .stop = behavioral_stop,
    .configure = behavioral_configure,
    .get_config = behavioral_get_config,
    .handle_event = behavioral_handle_event,
    .get_stats = behavioral_get_stats,
    .health_check = behavioral_health_check
};

// Plugin instance
static struct rootshield_plugin behavioral_plugin = {
    .metadata = &behavioral_metadata,
    .ops = &behavioral_ops,
    .state = PLUGIN_STATE_UNLOADED
};

// Statistical functions
static double calculate_mean(uint64_t *values, size_t count)
{
    uint64_t sum = 0;
    size_t i;

    for (i = 0; i < count; i++) {
        sum += values[i];
    }

    return (double)sum / count;
}

static double calculate_variance(uint64_t *values, size_t count, double mean)
{
    double variance = 0;
    size_t i;

    for (i = 0; i < count; i++) {
        double diff = (double)values[i] - mean;
        variance += diff * diff;
    }

    return variance / count;
}

static double calculate_std_dev(double variance)
{
    return sqrt(variance);
}

static void update_statistical_model(struct statistical_model *model, uint64_t new_value)
{
    if (!model->initialized) {
        // Initialize with first value
        memset(model->values, 0, model->window_size * sizeof(uint64_t));
        model->values[0] = new_value;
        model->current_index = 1;
        model->mean = new_value;
        model->variance = 0;
        model->std_dev = 0;
        model->min_value = new_value;
        model->max_value = new_value;
        model->initialized = true;
        return;
    }

    // Update sliding window
    model->values[model->current_index] = new_value;
    model->current_index = (model->current_index + 1) % model->window_size;

    // Recalculate statistics
    model->mean = calculate_mean(model->values, model->window_size);
    model->variance = calculate_variance(model->values, model->window_size, model->mean);
    model->std_dev = calculate_std_dev(model->variance);

    // Update min/max
    if (new_value < model->min_value) model->min_value = new_value;
    if (new_value > model->max_value) model->max_value = new_value;
}

static double detect_anomaly(struct statistical_model *model, uint64_t value)
{
    if (!model->initialized || model->std_dev == 0) {
        return 0.0; // Cannot detect anomaly without variance
    }

    double z_score = fabs((double)value - model->mean) / model->std_dev;

    if (z_score > model->threshold_multiplier) {
        model->consecutive_anomalies++;
        model->anomaly_count++;
    } else {
        model->consecutive_anomalies = 0;
    }

    return z_score;
}

// Process profile management
static struct process_profile *find_process_profile(struct behavioral_data *data, pid_t pid)
{
    struct rb_node *node = data->process_tree.rb_node;

    while (node) {
        struct process_profile *profile = rb_entry(node, struct process_profile, node);

        if (pid < profile->pid)
            node = node->rb_left;
        else if (pid > profile->pid)
            node = node->rb_right;
        else
            return profile;
    }

    return NULL;
}

static struct process_profile *create_process_profile(pid_t pid, const char *comm, uid_t uid)
{
    struct process_profile *profile;

    profile = kzalloc(sizeof(*profile), GFP_KERNEL);
    if (!profile)
        return NULL;

    profile->pid = pid;
    strlcpy(profile->comm, comm, sizeof(profile->comm));
    profile->uid = uid;
    profile->first_seen = ktime_get_real_ns();
    profile->last_seen = profile->first_seen;
    profile->anomaly_score = 0.0;

    // Initialize statistical models for each feature
    // This would be expanded with proper window sizes and thresholds

    return profile;
}

static void destroy_process_profile(struct process_profile *profile)
{
    if (profile) {
        kfree(profile);
    }
}

static int insert_process_profile(struct behavioral_data *data, struct process_profile *profile)
{
    struct rb_node **new = &(data->process_tree.rb_node), *parent = NULL;

    while (*new) {
        struct process_profile *this = rb_entry(*new, struct process_profile, node);
        parent = *new;

        if (profile->pid < this->pid)
            new = &((*new)->rb_left);
        else if (profile->pid > this->pid)
            new = &((*new)->rb_right);
        else
            return -EEXIST; // Profile already exists
    }

    rb_link_node(&profile->node, parent, new);
    rb_insert_color(&profile->node, &data->process_tree);

    atomic_inc(&data->profiles_active);
    return 0;
}

// Plugin operation implementations
static int behavioral_init(void *plugin_data)
{
    struct behavioral_data *data;
    int i;

    data = kzalloc(sizeof(*data), GFP_KERNEL);
    if (!data)
        return -ENOMEM;

    // Initialize red-black tree
    data->process_tree = RB_ROOT;
    spin_lock_init(&data->tree_lock);

    // Initialize global models
    for (i = 0; i < FEATURE_MAX; i++) {
        data->global_models[i].feature = i;
        strlcpy(data->global_models[i].name, feature_names[i],
                sizeof(data->global_models[i].name));
        data->global_models[i].window_size = 100; // Configurable
        data->global_models[i].threshold_multiplier = ANOMALY_THRESHOLD_MEDIUM;
        data->global_models[i].initialized = false;

        // Allocate sliding window
        data->global_models[i].values = kcalloc(data->global_models[i].window_size,
                                               sizeof(uint64_t), GFP_KERNEL);
        if (!data->global_models[i].values) {
            // Cleanup and return error
            while (i-- > 0) {
                kfree(data->global_models[i].values);
            }
            kfree(data);
            return -ENOMEM;
        }
    }

    // Default configuration
    data->analysis_window_seconds = ANALYSIS_WINDOW_MEDIUM;
    data->anomaly_threshold = ANOMALY_THRESHOLD_MEDIUM;
    data->adaptive_thresholds = true;
    data->max_profiles = 1000;

    // Initialize workqueue
    data->analysis_workqueue = create_singlethread_workqueue("rootshield_behavioral");
    if (!data->analysis_workqueue) {
        // Cleanup
        for (i = 0; i < FEATURE_MAX; i++) {
            kfree(data->global_models[i].values);
        }
        kfree(data);
        return -ENOMEM;
    }

    INIT_DELAYED_WORK(&data->analysis_work, behavioral_analysis_worker);

    behavioral_plugin.private_data = data;

    pr_info("RootShield: Behavioral analyzer initialized\n");
    return 0;
}

static void behavioral_exit(void *plugin_data)
{
    struct behavioral_data *data = plugin_data;
    struct process_profile *profile;
    struct rb_node *node;
    int i;

    if (data) {
        // Stop analysis work
        if (data->analysis_workqueue) {
            cancel_delayed_work_sync(&data->analysis_work);
            destroy_workqueue(data->analysis_workqueue);
        }

        // Clean up process profiles
        spin_lock(&data->tree_lock);
        for (node = rb_first(&data->process_tree); node; node = rb_next(node)) {
            profile = rb_entry(node, struct process_profile, node);
            rb_erase(&profile->node, &data->process_tree);
            destroy_process_profile(profile);
        }
        spin_unlock(&data->tree_lock);

        // Clean up global models
        for (i = 0; i < FEATURE_MAX; i++) {
            kfree(data->global_models[i].values);
        }

        kfree(data);
    }

    pr_info("RootShield: Behavioral analyzer exited\n");
}

static int behavioral_start(void *plugin_data)
{
    struct behavioral_data *data = plugin_data;

    // Start periodic analysis
    queue_delayed_work(data->analysis_workqueue, &data->analysis_work,
                      msecs_to_jiffies(data->analysis_window_seconds * 1000));

    pr_info("RootShield: Behavioral analyzer started\n");
    return 0;
}

static void behavioral_stop(void *plugin_data)
{
    struct behavioral_data *data = plugin_data;

    // Stop periodic analysis
    cancel_delayed_work_sync(&data->analysis_work);

    pr_info("RootShield: Behavioral analyzer stopped\n");
}

static int behavioral_configure(void *plugin_data, const char *key, const char *value)
{
    struct behavioral_data *data = plugin_data;

    if (strcmp(key, "analysis_window") == 0) {
        data->analysis_window_seconds = simple_strtoul(value, NULL, 10);
        return 0;
    } else if (strcmp(key, "anomaly_threshold") == 0) {
        data->anomaly_threshold = simple_strtod(value, NULL);
        return 0;
    } else if (strcmp(key, "adaptive_thresholds") == 0) {
        data->adaptive_thresholds = simple_strtoul(value, NULL, 10) != 0;
        return 0;
    } else if (strcmp(key, "max_profiles") == 0) {
        data->max_profiles = simple_strtoul(value, NULL, 10);
        return 0;
    }

    return -EINVAL;
}

static int behavioral_get_config(void *plugin_data, const char *key, char *value, size_t size)
{
    struct behavioral_data *data = plugin_data;

    if (strcmp(key, "analysis_window") == 0) {
        snprintf(value, size, "%u", data->analysis_window_seconds);
        return 0;
    } else if (strcmp(key, "anomaly_threshold") == 0) {
        snprintf(value, size, "%.2f", data->anomaly_threshold);
        return 0;
    } else if (strcmp(key, "adaptive_thresholds") == 0) {
        snprintf(value, size, "%d", data->adaptive_thresholds);
        return 0;
    } else if (strcmp(key, "max_profiles") == 0) {
        snprintf(value, size, "%u", data->max_profiles);
        return 0;
    }

    return -EINVAL;
}

static int behavioral_handle_event(void *plugin_data, struct security_event *event)
{
    struct behavioral_data *data = plugin_data;
    struct process_profile *profile;
    behavioral_feature_t feature;
    uint64_t feature_value = 1; // Default increment

    // Map event types to behavioral features
    switch (event->type) {
    case EVENT_SYSCALL_EXECUTED:
        feature = FEATURE_SYSCALL_FREQUENCY;
        break;
    case EVENT_PROCESS_CREATED:
        feature = FEATURE_PROCESS_SPAWN_RATE;
        break;
    case EVENT_FILE_ACCESS:
        feature = FEATURE_FILE_ACCESS_PATTERNS;
        break;
    case EVENT_NETWORK_CONNECTION:
        feature = FEATURE_NETWORK_CONNECTIONS;
        break;
    default:
        return 0; // Event not relevant for behavioral analysis
    }

    // Update global model
    update_statistical_model(&data->global_models[feature], feature_value);

    // Check for global anomaly
    double z_score = detect_anomaly(&data->global_models[feature], feature_value);
    if (z_score > data->anomaly_threshold) {
        // Global anomaly detected
        atomic_inc(&data->anomalies_detected);

        struct security_event anomaly_event = {
            .type = EVENT_ANOMALY_DETECTED,
            .severity = EVENT_SEVERITY_WARNING,
            .source = BEHAVIORAL_PLUGIN_NAME,
            .timestamp = ktime_get_real_ns(),
            .pid = event->pid,
        };

        snprintf(anomaly_event.path, sizeof(anomaly_event.path),
                "Global anomaly in %s (z-score: %.2f)",
                feature_names[feature], z_score);

        publish_event(&anomaly_event);
    }

    // Update process-specific profile
    spin_lock(&data->tree_lock);
    profile = find_process_profile(data, event->pid);
    if (!profile) {
        // Create new profile
        profile = create_process_profile(event->pid, "unknown", 0);
        if (profile) {
            insert_process_profile(data, profile);
        }
    }

    if (profile) {
        profile->last_seen = ktime_get_real_ns();
        profile->event_count++;

        // Update process-specific model
        update_statistical_model(&profile->models[feature], feature_value);

        // Check for process-specific anomaly
        z_score = detect_anomaly(&profile->models[feature], feature_value);
        if (z_score > data->anomaly_threshold) {
            profile->anomaly_score += z_score;

            if (profile->anomaly_score > data->anomaly_threshold * 2) {
                // Process-specific anomaly detected
                atomic_inc(&data->anomalies_detected);

                struct security_event anomaly_event = {
                    .type = EVENT_ANOMALY_DETECTED,
                    .severity = EVENT_SEVERITY_HIGH,
                    .source = BEHAVIORAL_PLUGIN_NAME,
                    .timestamp = ktime_get_real_ns(),
                    .pid = event->pid,
                };

                snprintf(anomaly_event.path, sizeof(anomaly_event.path),
                        "Process anomaly in %s (z-score: %.2f, cumulative: %.2f)",
                        feature_names[feature], z_score, profile->anomaly_score);

                publish_event(&anomaly_event);
            }
        }
    }
    spin_unlock(&data->tree_lock);

    return 0;
}

static int behavioral_get_stats(void *plugin_data, struct plugin_stats *stats)
{
    struct behavioral_data *data = plugin_data;

    stats->events_processed = 0; // Would track actual events
    stats->alerts_generated = atomic_read(&data->anomalies_detected);
    stats->blocks_performed = 0; // Behavioral analysis typically alerts
    stats->errors_encountered = atomic_read(&data->false_positives);
    stats->uptime_seconds = 0; // Would calculate actual uptime
    stats->memory_usage_kb = (sizeof(struct behavioral_data) +
                             atomic_read(&data->profiles_active) * sizeof(struct process_profile)) / 1024;

    return 0;
}

static int behavioral_health_check(void *plugin_data)
{
    struct behavioral_data *data = plugin_data;

    // Basic health checks
    if (!data || !data->analysis_workqueue)
        return -EINVAL;

    return 0;
}

static void behavioral_analysis_worker(struct work_struct *work)
{
    struct behavioral_data *data = container_of(work, struct behavioral_data, analysis_work.work);
    struct process_profile *profile;
    struct rb_node *node;
    uint64_t current_time = ktime_get_real_ns();
    uint64_t cleanup_threshold = current_time - (data->analysis_window_seconds * 2 * NSEC_PER_SEC);

    // Periodic cleanup of old profiles
    spin_lock(&data->tree_lock);
    for (node = rb_first(&data->process_tree); node; ) {
        profile = rb_entry(node, struct process_profile, node);
        node = rb_next(node); // Advance before potential removal

        if (profile->last_seen < cleanup_threshold &&
            atomic_read(&data->profiles_active) > data->max_profiles) {
            rb_erase(&profile->node, &data->process_tree);
            destroy_process_profile(profile);
            atomic_dec(&data->profiles_active);
        }
    }
    spin_unlock(&data->tree_lock);

    // Adaptive threshold adjustment
    if (data->adaptive_thresholds) {
        // Adjust thresholds based on recent activity
        // Implementation would analyze recent anomaly rates
    }

    // Reschedule next analysis
    queue_delayed_work(data->analysis_workqueue, &data->analysis_work,
                      msecs_to_jiffies(data->analysis_window_seconds * 1000));
}

// Plugin registration
static int __init behavioral_plugin_init(void)
{
    return register_plugin(&behavioral_plugin);
}

static void __exit behavioral_plugin_exit(void)
{
    unregister_plugin(&behavioral_plugin);
}

module_init(behavioral_plugin_init);
module_exit(behavioral_plugin_exit);

MODULE_LICENSE("GPL-3.0");
MODULE_AUTHOR("@ImKKingshuk");
MODULE_DESCRIPTION("RootShield Behavioral Analysis Plugin");
