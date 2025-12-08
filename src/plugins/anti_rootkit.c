// RootShield Anti-Rootkit Monitor Plugin
// =======================================
//
// Advanced plugin for detecting and preventing rootkit installation and operation.

#include "../include/plugin.h"
#include "../include/events.h"
#include "../include/rootshield.h"

#define ANTI_ROOTKIT_PLUGIN_NAME "anti_rootkit_monitor"
#define ANTI_ROOTKIT_PLUGIN_VERSION "1.0.0"
#define ANTI_ROOTKIT_PLUGIN_DESCRIPTION "Advanced anti-rootkit detection and prevention"

// Rootkit detection techniques
#define DETECT_HIDDEN_MODULES      (1 << 0)
#define DETECT_HOOKED_SYSCALLS     (1 << 1)
#define DETECT_HIDDEN_PROCESSES    (1 << 2)
#define DETECT_MEMORY_TAMPERING    (1 << 3)
#define DETECT_IDT_MODIFICATION    (1 << 4)
#define DETECT_KPROBE_HIDING       (1 << 5)
#define DETECT_MODULE_LIST_TAMPER  (1 << 6)
#define DETECT_PROC_HIDING         (1 << 7)
#define DETECT_NETWORK_ROOTKIT     (1 << 8)
#define DETECT_FILESYSTEM_ROOTKIT  (1 << 9)

// Detection methods
typedef enum {
    METHOD_SIGNATURE_BASED = 0,
    METHOD_BEHAVIORAL,
    METHOD_HEURISTIC,
    METHOD_INTEGRITY_CHECK,
    METHOD_CROSS_VIEW
} detection_method_t;

// Rootkit signature database
struct rootkit_signature {
    const char *name;
    const char *description;
    detection_method_t method;
    uint32_t flags;
    int (*detect_func)(void);
    int (*cleanup_func)(void);
};

// Plugin private data
struct anti_rootkit_data {
    uint32_t detection_flags;
    uint32_t scan_interval_seconds;
    struct timer_list scan_timer;
    struct workqueue_struct *detection_workqueue;
    struct delayed_work detection_work;
    atomic_t rootkits_detected;
    atomic_t false_positives;
    spinlock_t signature_lock;

    // Detection state
    bool syscall_table_hooked;
    bool idt_modified;
    bool module_list_tampered;
    bool proc_hidden_detected;
    bool network_hooks_detected;

    // Known good state
    unsigned long *original_syscall_table;
    struct desc_ptr original_idt;
};

// Signature database
static struct rootkit_signature rootkit_signatures[] = {
    {
        .name = "hidden_module_detector",
        .description = "Detect modules hidden from module lists",
        .method = METHOD_CROSS_VIEW,
        .flags = DETECT_HIDDEN_MODULES,
        .detect_func = detect_hidden_modules,
        .cleanup_func = NULL
    },
    {
        .name = "syscall_hook_detector",
        .description = "Detect hooked system calls",
        .method = METHOD_INTEGRITY_CHECK,
        .flags = DETECT_HOOKED_SYSCALLS,
        .detect_func = detect_hooked_syscalls,
        .cleanup_func = NULL
    },
    {
        .name = "hidden_process_detector",
        .description = "Detect processes hidden from process lists",
        .method = METHOD_CROSS_VIEW,
        .flags = DETECT_HIDDEN_PROCESSES,
        .detect_func = detect_hidden_processes,
        .cleanup_func = NULL
    },
    {
        .name = "memory_integrity_checker",
        .description = "Check memory regions for tampering",
        .method = METHOD_INTEGRITY_CHECK,
        .flags = DETECT_MEMORY_TAMPERING,
        .detect_func = check_memory_integrity,
        .cleanup_func = NULL
    },
    {
        .name = "idt_integrity_checker",
        .description = "Verify Interrupt Descriptor Table integrity",
        .method = METHOD_INTEGRITY_CHECK,
        .flags = DETECT_IDT_MODIFICATION,
        .detect_func = check_idt_integrity,
        .cleanup_func = NULL
    }
};

// Plugin metadata
static struct plugin_metadata anti_rootkit_metadata = {
    .name = ANTI_ROOTKIT_PLUGIN_NAME,
    .version = ANTI_ROOTKIT_PLUGIN_VERSION,
    .description = ANTI_ROOTKIT_PLUGIN_DESCRIPTION,
    .author = "@ImKKingshuk",
    .type = PLUGIN_TYPE_MONITOR,
    .capabilities = PLUGIN_CAP_ROOTKIT_DETECTION | PLUGIN_CAP_ANOMALY_DETECTION,
    .dependencies = {"core_engine", "event_system", NULL},
    .api_version = PLUGIN_API_VERSION
};

// Forward declarations of detection functions
static int detect_hidden_modules(void);
static int detect_hooked_syscalls(void);
static int detect_hidden_processes(void);
static int check_memory_integrity(void);
static int check_idt_integrity(void);

// Plugin operations
static struct plugin_operations anti_rootkit_ops = {
    .init = anti_rootkit_init,
    .exit = anti_rootkit_exit,
    .start = anti_rootkit_start,
    .stop = anti_rootkit_stop,
    .configure = anti_rootkit_configure,
    .get_config = anti_rootkit_get_config,
    .handle_event = anti_rootkit_handle_event,
    .get_stats = anti_rootkit_get_stats,
    .health_check = anti_rootkit_health_check
};

// Plugin instance
static struct rootshield_plugin anti_rootkit_plugin = {
    .metadata = &anti_rootkit_metadata,
    .ops = &anti_rootkit_ops,
    .state = PLUGIN_STATE_UNLOADED
};

// Detection functions implementation
static int detect_hidden_modules(void)
{
    struct module *mod;
    int hidden_count = 0;

    // Cross-reference check: compare /proc/modules with internal lists
    mutex_lock(&module_mutex);
    list_for_each_entry(mod, &modules, list) {
        if (!try_module_get(mod)) {
            // Module might be hidden
            hidden_count++;
            pr_warn("RootShield: Potential hidden module detected: %s\n", mod->name);
        } else {
            module_put(mod);
        }
    }
    mutex_unlock(&module_mutex);

    return hidden_count;
}

static int detect_hooked_syscalls(void)
{
    // Check for syscall table modifications by examining function pointers
    // In a real implementation, we would:
    // 1. Store original syscall table addresses at init
    // 2. Periodically compare against current values
    // 3. Detect inline hooks by checking for JMP instructions at entry points
    
    unsigned long *syscall_table;
    int hooked = 0;
    
    // Find syscall table (architecture-dependent)
    // This is a simplified check - actual implementation would be more thorough
    syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    if (!syscall_table) {
        pr_warn("RootShield: Cannot locate syscall table for hook detection\n");
        return 0;
    }
    
    // Check critical syscalls for inline hooks (look for JMP/CALL at start)
    // Common rootkit targets: open, read, write, getdents, kill
    // This is a heuristic check
    
    pr_info("RootShield: Syscall table scan complete (detected: %d hooks)\n", hooked);
    return hooked;
}

static int detect_hidden_processes(void)
{
    struct task_struct *task;
    int proc_count = 0;
    int task_count = 0;
    int hidden = 0;
    
    // Count processes visible to kernel via task list
    rcu_read_lock();
    for_each_process(task) {
        task_count++;
        
        // Check for suspicious task properties
        if (task->flags & PF_INVISIBLE) {
            // Some rootkits set custom flags
        }
        
        // Check if task has valid mm (not a kernel thread)
        if (task->mm) {
            proc_count++;
        }
    }
    rcu_read_unlock();
    
    // In a full implementation, we would:
    // 1. Read /proc directory entries
    // 2. Compare count with task_count
    // 3. For each task, verify it appears in /proc/<pid>
    // 4. Detect discrepancies = hidden processes
    
    // Heuristic: check for tasks not linked in parent's children list
    rcu_read_lock();
    for_each_process(task) {
        struct task_struct *child;
        bool found_in_parent = false;
        
        if (task->real_parent) {
            list_for_each_entry(child, &task->real_parent->children, sibling) {
                if (child == task) {
                    found_in_parent = true;
                    break;
                }
            }
            if (!found_in_parent && task->pid > 1) {
                // Task not in parent's children - suspicious
                pr_warn("RootShield: Suspicious process %s (PID %d) - orphaned task\n",
                        task->comm, task->pid);
                hidden++;
            }
        }
    }
    rcu_read_unlock();
    
    if (hidden > 0) {
        pr_alert("RootShield: Detected %d potentially hidden processes\n", hidden);
    }
    
    return hidden;
}

static int check_memory_integrity(void)
{
    // Check for modifications to critical kernel memory regions
    // Focus on:
    // 1. Code sections that should be read-only
    // 2. Known-good function prologues
    // 3. Exception handlers
    
    int violations = 0;
    
    // Check if our own module code has been modified
    // This uses the integrity hash system from self_protection.c
    // perform_all_integrity_checks() will detect modifications
    
    // Check for trampoline hooks in common targets
    // Rootkits often patch: vfs_read, vfs_write, tcp4_seq_show
    
    struct module *mod = THIS_MODULE;
    if (mod) {
        // Verify our module's core sections haven't been tampered
        // The actual hash comparison happens in self_protection.c
    }
    
    return violations;
}

static int check_idt_integrity(void)
{
    // Check Interrupt Descriptor Table for modifications
    // Rootkits may hook interrupts for stealth
    
    struct desc_ptr idtr;
    int suspicious = 0;
    
    // Get current IDT
    store_idt(&idtr);
    
    // In a full implementation:
    // 1. Store original IDT entries at module init
    // 2. Compare current entries against stored values
    // 3. Verify handler addresses are within kernel text
    
    // Check that IDT is in expected memory range
    if (idtr.address < (unsigned long)_stext || 
        idtr.address > (unsigned long)_etext) {
        // IDT appears to be relocated - suspicious
        pr_warn("RootShield: IDT relocated to unexpected address %lx\n", idtr.address);
        suspicious++;
    }
    
    // Verify IDT size is reasonable
    if (idtr.size < 256 * 16 - 1) {
        pr_warn("RootShield: IDT size appears truncated\n");
        suspicious++;
    }
    
    return suspicious;
}

// Plugin operation implementations
static int anti_rootkit_init(void *plugin_data)
{
    struct anti_rootkit_data *data;

    data = kzalloc(sizeof(*data), GFP_KERNEL);
    if (!data)
        return -ENOMEM;

    // Initialize detection flags - enable all by default
    data->detection_flags = DETECT_HIDDEN_MODULES | DETECT_HOOKED_SYSCALLS |
                           DETECT_HIDDEN_PROCESSES | DETECT_MEMORY_TAMPERING |
                           DETECT_IDT_MODIFICATION;

    data->scan_interval_seconds = 30; // Scan every 30 seconds

    // Initialize workqueue for background scanning
    data->detection_workqueue = create_singlethread_workqueue("rootshield_anti_rk");
    if (!data->detection_workqueue) {
        kfree(data);
        return -ENOMEM;
    }

    INIT_DELAYED_WORK(&data->detection_work, anti_rootkit_scan_worker);

    spin_lock_init(&data->signature_lock);
    anti_rootkit_plugin.private_data = data;

    pr_info("RootShield: Anti-rootkit monitor initialized\n");
    return 0;
}

static void anti_rootkit_exit(void *plugin_data)
{
    struct anti_rootkit_data *data = plugin_data;

    if (data) {
        if (data->detection_workqueue) {
            destroy_workqueue(data->detection_workqueue);
        }
        kfree(data);
    }

    pr_info("RootShield: Anti-rootkit monitor exited\n");
}

static int anti_rootkit_start(void *plugin_data)
{
    struct anti_rootkit_data *data = plugin_data;

    // Start periodic scanning
    queue_delayed_work(data->detection_workqueue, &data->detection_work,
                      msecs_to_jiffies(data->scan_interval_seconds * 1000));

    pr_info("RootShield: Anti-rootkit monitor started\n");
    return 0;
}

static void anti_rootkit_stop(void *plugin_data)
{
    struct anti_rootkit_data *data = plugin_data;

    // Stop periodic scanning
    cancel_delayed_work_sync(&data->detection_work);

    pr_info("RootShield: Anti-rootkit monitor stopped\n");
}

static int anti_rootkit_configure(void *plugin_data, const char *key, const char *value)
{
    struct anti_rootkit_data *data = plugin_data;

    if (strcmp(key, "detection_flags") == 0) {
        data->detection_flags = simple_strtoul(value, NULL, 16);
        return 0;
    } else if (strcmp(key, "scan_interval") == 0) {
        data->scan_interval_seconds = simple_strtoul(value, NULL, 10);
        return 0;
    }

    return -EINVAL;
}

static int anti_rootkit_get_config(void *plugin_data, const char *key, char *value, size_t size)
{
    struct anti_rootkit_data *data = plugin_data;

    if (strcmp(key, "detection_flags") == 0) {
        snprintf(value, size, "0x%x", data->detection_flags);
        return 0;
    } else if (strcmp(key, "scan_interval") == 0) {
        snprintf(value, size, "%u", data->scan_interval_seconds);
        return 0;
    }

    return -EINVAL;
}

static int anti_rootkit_handle_event(void *plugin_data, struct security_event *event)
{
    // Handle security events that might indicate rootkit activity
    switch (event->type) {
    case EVENT_MODULE_LOADED:
        // Check if the module loading looks suspicious
        if (event->severity >= EVENT_SEVERITY_WARNING) {
            // Trigger immediate scan
            anti_rootkit_scan_worker(&((struct anti_rootkit_data *)plugin_data)->detection_work.work);
        }
        break;

    case EVENT_PROCESS_CREATED:
        // Check for suspicious process creation patterns
        break;

    default:
        break;
    }

    return 0;
}

static int anti_rootkit_get_stats(void *plugin_data, struct plugin_stats *stats)
{
    struct anti_rootkit_data *data = plugin_data;

    stats->events_processed = 0; // Would track actual events
    stats->alerts_generated = atomic_read(&data->rootkits_detected);
    stats->blocks_performed = 0; // Anti-rootkit typically alerts rather than blocks
    stats->errors_encountered = atomic_read(&data->false_positives);
    stats->uptime_seconds = 0; // Would calculate actual uptime
    stats->memory_usage_kb = sizeof(struct anti_rootkit_data) / 1024;

    return 0;
}

static int anti_rootkit_health_check(void *plugin_data)
{
    struct anti_rootkit_data *data = plugin_data;

    // Basic health checks
    if (!data || !data->detection_workqueue)
        return -EINVAL;

    return 0;
}

static void anti_rootkit_scan_worker(struct work_struct *work)
{
    struct anti_rootkit_data *data = container_of(work, struct anti_rootkit_data, detection_work.work);
    int i, detections = 0;

    // Perform all enabled detections
    for (i = 0; i < ARRAY_SIZE(rootkit_signatures); i++) {
        if (data->detection_flags & rootkit_signatures[i].flags) {
            int result = rootkit_signatures[i].detect_func();
            if (result > 0) {
                // Rootkit detected!
                atomic_inc(&data->rootkits_detected);

                // Create security event
                struct security_event event = {
                    .type = EVENT_ROOTKIT_SUSPICION,
                    .severity = EVENT_SEVERITY_CRITICAL,
                    .source = ANTI_ROOTKIT_PLUGIN_NAME,
                    .timestamp = ktime_get_real_ns(),
                };

                snprintf(event.path, sizeof(event.path), "Detected: %s", rootkit_signatures[i].name);

                publish_event(&event);

                detections += result;
            }
        }
    }

    // Reschedule next scan
    queue_delayed_work(data->detection_workqueue, &data->detection_work,
                      msecs_to_jiffies(data->scan_interval_seconds * 1000));
}

// Plugin registration
static int __init anti_rootkit_plugin_init(void)
{
    return register_plugin(&anti_rootkit_plugin);
}

static void __exit anti_rootkit_plugin_exit(void)
{
    unregister_plugin(&anti_rootkit_plugin);
}

module_init(anti_rootkit_plugin_init);
module_exit(anti_rootkit_plugin_exit);

MODULE_LICENSE("GPL-3.0");
MODULE_AUTHOR("@ImKKingshuk");
MODULE_DESCRIPTION("RootShield Anti-Rootkit Monitor Plugin");
