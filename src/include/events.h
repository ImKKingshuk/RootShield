// RootShield Event System
// ========================
//
// Publish-subscribe event system for inter-plugin communication and
// centralized event processing.

#ifndef ROOTSHIELD_EVENTS_H
#define ROOTSHIELD_EVENTS_H

#include <linux/module.h>
#include <linux/kfifo.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>

// Event types
typedef enum {
    EVENT_SECURITY_VIOLATION = 0,
    EVENT_SECURITY_BLOCK,
    EVENT_SECURITY_ALLOW,
    EVENT_PROCESS_CREATED,
    EVENT_PROCESS_TERMINATED,
    EVENT_FILE_ACCESS,
    EVENT_FILE_MODIFIED,
    EVENT_NETWORK_CONNECTION,
    EVENT_SYSCALL_EXECUTED,
    EVENT_MEMORY_ACCESS,
    EVENT_MODULE_LOADED,
    EVENT_ANOMALY_DETECTED,
    EVENT_ROOTKIT_SUSPICION,
    EVENT_CONFIGURATION_CHANGE,
    EVENT_PLUGIN_STATE_CHANGE,
    EVENT_SYSTEM_HEALTH_CHECK,
    EVENT_FORENSICS_DATA,
    EVENT_CUSTOM = 1000  // Start of custom event range
} event_type_t;

// Event priorities
typedef enum {
    EVENT_PRIORITY_LOW = 0,
    EVENT_PRIORITY_NORMAL,
    EVENT_PRIORITY_HIGH,
    EVENT_PRIORITY_CRITICAL
} event_priority_t;

// Event severity levels
typedef enum {
    EVENT_SEVERITY_INFO = 0,
    EVENT_SEVERITY_WARNING,
    EVENT_SEVERITY_ERROR,
    EVENT_SEVERITY_CRITICAL
} event_severity_t;

// Event structure
struct security_event {
    uint64_t id;                    // Unique event ID
    uint64_t timestamp;             // Event timestamp (nanoseconds)
    event_type_t type;              // Event type
    event_priority_t priority;      // Event priority
    event_severity_t severity;      // Event severity
    const char *source;             // Source plugin/component name
    uint32_t pid;                   // Process ID
    uint32_t uid;                   // User ID
    uint32_t gid;                   // Group ID
    char comm[16];                  // Command name
    char path[256];                 // File path or network address
    void *data;                     // Event-specific data
    size_t data_size;               // Size of event data
    uint32_t flags;                 // Event flags
};

// Event subscriber structure
struct event_subscriber {
    const char *name;                           // Subscriber name
    void (*callback)(struct security_event *);  // Event callback function
    uint32_t subscribed_events;                 // Bitmask of subscribed events
    struct list_head list;                      // List head for subscriber list
    spinlock_t lock;                            // Subscriber lock
    atomic_t active;                            // Subscriber active flag
};

// Event queue structure
struct event_queue {
    struct kfifo fifo;              // Kernel FIFO for event storage
    spinlock_t lock;                // Queue lock
    wait_queue_head_t wait_queue;   // Wait queue for consumers
    atomic_t producers;             // Number of active producers
    atomic_t consumers;             // Number of active consumers
};

// Event dispatcher structure
struct event_dispatcher {
    struct event_queue queue;           // Main event queue
    struct list_head subscribers;       // List of subscribers
    spinlock_t subscribers_lock;        // Subscribers list lock
    struct workqueue_struct *workqueue; // Workqueue for async processing
    struct delayed_work dispatch_work;  // Delayed work for batch processing
    atomic_t running;                   // Dispatcher running flag
};

// Event filter structure for rule-based filtering
struct event_filter {
    event_type_t event_type;        // Event type to filter
    const char *source_pattern;     // Source pattern (glob matching)
    uint32_t pid_range_start;       // PID range start
    uint32_t pid_range_end;         // PID range end
    uint32_t uid_range_start;       // UID range start
    uint32_t uid_range_end;         // UID range end
    const char *path_pattern;       // Path pattern (glob matching)
    event_severity_t min_severity;  // Minimum severity level
    uint32_t custom_flags;          // Custom filter flags
};

// Core event system functions
extern int init_event_system(void);
extern void exit_event_system(void);

// Event publishing functions
extern int publish_event(struct security_event *event);
extern int publish_event_async(struct security_event *event);

// Event subscription functions
extern int subscribe_to_events(const char *subscriber_name,
                              void (*callback)(struct security_event *),
                              uint32_t event_mask);
extern int unsubscribe_from_events(const char *subscriber_name);

// Event filtering functions
extern int register_event_filter(struct event_filter *filter);
extern void unregister_event_filter(struct event_filter *filter);

// Event processing functions
extern int process_pending_events(void);
extern int get_pending_event_count(void);

// Event statistics
extern void get_event_stats(uint64_t *total_events,
                           uint64_t *processed_events,
                           uint64_t *dropped_events);

// Utility functions
extern struct security_event *create_security_event(event_type_t type,
                                                   event_severity_t severity,
                                                   const char *source);
extern void destroy_security_event(struct security_event *event);
extern int copy_security_event(struct security_event *dst,
                              const struct security_event *src);

// Event serialization for logging/networking
extern int serialize_event(const struct security_event *event,
                          void *buffer, size_t buffer_size);
extern int deserialize_event(struct security_event *event,
                            const void *buffer, size_t buffer_size);

// Event debugging
extern void dump_event(const struct security_event *event);
extern void enable_event_debugging(bool enable);

#endif /* ROOTSHIELD_EVENTS_H */
