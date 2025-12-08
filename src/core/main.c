//  RootShield
//  Author: @ImKKingshuk

#include "../include/rootshield.h"
#include "../include/runtime_config.h"
#include "../include/statistics.h"
#include "../include/notification.h"
#include "../include/events.h"
#include "../include/rules.h"
#include "../include/plugin.h"
#include "../include/self_protection.h"

// Forward declarations for new systems
extern int init_event_system(void);
extern void exit_event_system(void);
extern int init_rule_engine(void);
extern void exit_rule_engine(void);
extern int init_plugin_manager(void);
extern void exit_plugin_manager(void);
extern int init_self_protection(protection_level_t level);
extern void exit_self_protection(void);

void print_banner(void) {
    const char *banner[] = {
        "***************************************************",
        "*                     RootShield                  *",
        "*  The Ultimate Shield for Rooted Android Device  *",
        "*                       v3.0.0                    *",
        "*           ----------------------------          *",
        "*                                 by @ImKKingshuk *",
        "*     Github- https://github.com/ImKKingshuk      *",
        "***************************************************"
    };

    for (int i = 0; i < sizeof(banner) / sizeof(banner[0]); i++) {
        pr_info("%s\n", banner[i]);
    }
}

static int __init root_shield_init(void) {
    int ret = 0;
    print_banner();

    pr_info("RootShield v3.0 initializing");
    
    // Initialize runtime configuration
    init_runtime_config();
    if (!validate_security_policy()) {
        pr_err("Failed to validate security policy");
        return -EINVAL;
    }
    print_runtime_config();
    
    // Initialize statistics
    init_statistics();
    
    // Initialize notification system
    ret = init_notification_system();
    if (ret < 0) {
        pr_err("Failed to initialize notification system: %d", ret);
        goto cleanup_stats;
    }
    
    // Initialize event system (v3.0)
    ret = init_event_system();
    if (ret < 0) {
        pr_err("Failed to initialize event system: %d", ret);
        goto cleanup_notification;
    }
    
    // Initialize rule engine (v3.0)
    ret = init_rule_engine();
    if (ret < 0) {
        pr_err("Failed to initialize rule engine: %d", ret);
        goto cleanup_events;
    }
    
    // Initialize plugin manager (v3.0)
    ret = init_plugin_manager();
    if (ret < 0) {
        pr_err("Failed to initialize plugin manager: %d", ret);
        goto cleanup_rules;
    }
    
    // Initialize self-protection (v3.0)
    ret = init_self_protection(PROTECTION_LEVEL_STANDARD);
    if (ret < 0) {
        pr_warn("Self-protection init failed: %d (continuing anyway)", ret);
        // Don't fail completely - self-protection is optional
    }

if (exec_monitor_enabled) {
    if (register_exec_monitor() < 0) {
        pr_err("Failed to register exec monitor");
        return -1;
    }
}

if (file_monitor_enabled) {
    if (register_file_monitor() < 0) {
        pr_err("Failed to register file monitor");
        goto cleanup_exec;
        return -1;
    }
}

if (process_monitor_enabled) {
    if (register_process_monitor() < 0) {
        pr_err("Failed to register process monitor");
        goto cleanup_file;
        return -1;
    }
}
    
if (network_monitor_enabled) {
    if (register_network_monitor() < 0) {
        pr_err("Failed to register network monitor");
        goto cleanup_process;
        return -1;
    }
}
    
if (syscall_monitor_enabled) {
    if (register_syscall_monitor() < 0) {
        pr_err("Failed to register syscall monitor");
        goto cleanup_network;
        return -1;
    }
}

if (memory_monitor_enabled) {
    if (register_memory_monitor() < 0) {
        pr_err("Failed to register memory monitor");
        goto cleanup_syscall;
        return -1;
    }
}

if (module_monitor_enabled) {
    if (register_module_monitor() < 0) {
        pr_err("Failed to register module monitor");
        goto cleanup_memory;
        return -1;
    }
}

    pr_info("RootShield v%s initialized successfully", ROOTSHIELD_VERSION_STR);
    return 0;

cleanup_memory:
if (memory_monitor_enabled) {
    unregister_memory_monitor();
}

cleanup_syscall:
if (syscall_monitor_enabled) {
    unregister_syscall_monitor();
}

cleanup_network:
if (network_monitor_enabled) {
    unregister_network_monitor();
}

cleanup_process:
if (process_monitor_enabled) {
    unregister_process_monitor();
}

cleanup_file:
if (file_monitor_enabled) {
    unregister_file_monitor();
}

cleanup_exec:
if (exec_monitor_enabled) {
    unregister_exec_monitor();
}

cleanup_rules:
    exit_rule_engine();
    
cleanup_events:
    exit_event_system();
    
cleanup_notification:
    cleanup_notification_system();

cleanup_stats:
    return -1;
}

static void __exit root_shield_exit(void) {
    pr_info("RootShield v%s exiting", ROOTSHIELD_VERSION_STR);
    
    // Exit self-protection first (to allow unloading)
    exit_self_protection();
    
    // Exit plugin manager
    exit_plugin_manager();
    
    // Exit rule engine
    exit_rule_engine();
    
    // Exit event system
    exit_event_system();
    
    // Clean up notification system
    cleanup_notification_system();
    
    // Print final statistics before unloading
    print_statistics();
    
    // Unregister all monitors
    if (module_monitor_enabled) {
        unregister_module_monitor();
    }
    if (memory_monitor_enabled) {
        unregister_memory_monitor();
    }
    if (syscall_monitor_enabled) {
        unregister_syscall_monitor();
    }
    if (network_monitor_enabled) {
        unregister_network_monitor();
    }
    if (process_monitor_enabled) {
        unregister_process_monitor();
    }
    if (file_monitor_enabled) {
        unregister_file_monitor();
    }
    if (exec_monitor_enabled) {
        unregister_exec_monitor();
    }
    
    pr_info("RootShield shutdown complete");
}

module_init(root_shield_init);
module_exit(root_shield_exit);

MODULE_LICENSE("GPL-3.0");
MODULE_AUTHOR("@ImKKingshuk");
MODULE_DESCRIPTION("The Ultimate Shield for Rooted Android Devices");