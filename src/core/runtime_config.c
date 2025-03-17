//  RootShield
//  Author: @ImKKingshuk

#include "../include/rootshield.h"
#include "../include/config.h"
#include "../include/runtime_config.h"

// Define module parameters that can be set at load time
bool exec_monitor_enabled = true;
module_param(exec_monitor_enabled, bool, 0644);
MODULE_PARM_DESC(exec_monitor_enabled, "Enable/disable execution monitoring");

bool file_monitor_enabled = true;
module_param(file_monitor_enabled, bool, 0644);
MODULE_PARM_DESC(file_monitor_enabled, "Enable/disable file system monitoring");

bool process_monitor_enabled = true;
module_param(process_monitor_enabled, bool, 0644);
MODULE_PARM_DESC(process_monitor_enabled, "Enable/disable process monitoring");

bool network_monitor_enabled = true;
module_param(network_monitor_enabled, bool, 0644);
MODULE_PARM_DESC(network_monitor_enabled, "Enable/disable network monitoring");

bool syscall_monitor_enabled = true;
module_param(syscall_monitor_enabled, bool, 0644);
MODULE_PARM_DESC(syscall_monitor_enabled, "Enable/disable syscall monitoring");

bool memory_monitor_enabled = true;
module_param(memory_monitor_enabled, bool, 0644);
MODULE_PARM_DESC(memory_monitor_enabled, "Enable/disable memory monitoring");

bool module_monitor_enabled = true;
module_param(module_monitor_enabled, bool, 0644);
MODULE_PARM_DESC(module_monitor_enabled, "Enable/disable kernel module monitoring");

// Security response configuration
bool kill_violating_process = true;
module_param(kill_violating_process, bool, 0644);
MODULE_PARM_DESC(kill_violating_process, "Kill processes that violate security policies");

bool notify_only = false;
module_param(notify_only, bool, 0644);
MODULE_PARM_DESC(notify_only, "Only log violations without taking action");

bool block_only = false;
module_param(block_only, bool, 0644);
MODULE_PARM_DESC(block_only, "Block operations without killing the process");

// Logging configuration
bool verbose_logging = false;
module_param(verbose_logging, bool, 0644);
MODULE_PARM_DESC(verbose_logging, "Enable verbose logging for debugging");

// Initialize runtime configuration with defaults from config.h
void init_runtime_config(void) {
    exec_monitor_enabled = ENABLE_EXEC_MONITOR;
    file_monitor_enabled = ENABLE_FILE_MONITOR;
    process_monitor_enabled = ENABLE_PROCESS_MONITOR;
    network_monitor_enabled = ENABLE_NETWORK_MONITOR;
    syscall_monitor_enabled = ENABLE_SYSCALL_MONITOR;
    memory_monitor_enabled = ENABLE_MEMORY_MONITOR;
    module_monitor_enabled = ENABLE_MODULE_MONITOR;
    
    kill_violating_process = SECURITY_ACTION_KILL_PROCESS;
    notify_only = SECURITY_ACTION_NOTIFY_ONLY;
    block_only = SECURITY_ACTION_BLOCK_ONLY;
    
    verbose_logging = false; // Default to minimal logging
}

// Validate security policy configuration
static bool validate_security_policy(void) {
    // Ensure at least one security action is enabled
    if (!kill_violating_process && !notify_only && !block_only) {
        pr_err("RootShield: Invalid security policy - no action enabled\n");
        return false;
    }
    
    // Prevent conflicting security actions
    if ((kill_violating_process && notify_only) ||
        (kill_violating_process && block_only) ||
        (notify_only && block_only)) {
        pr_err("RootShield: Invalid security policy - conflicting actions\n");
        return false;
    }
    
    return true;
}

// Apply runtime configuration to affect module behavior
void apply_runtime_config(void) {
    if (!validate_security_policy()) {
        // Set safe defaults if validation fails
        notify_only = true;
        kill_violating_process = false;
        block_only = false;
        pr_warn("RootShield: Applied safe default security policy\n");
    }
    
    pr_info("RootShield: Applied runtime configuration");
}

// Print current configuration for debugging
void print_runtime_config(void) {
    pr_info("RootShield Runtime Configuration:");
    pr_info("  Monitors: exec=%d, file=%d, process=%d, network=%d, syscall=%d, memory=%d, module=%d",
            exec_monitor_enabled, file_monitor_enabled, process_monitor_enabled,
            network_monitor_enabled, syscall_monitor_enabled, memory_monitor_enabled,
            module_monitor_enabled);
    pr_info("  Security Response: kill=%d, notify_only=%d, block_only=%d",
            kill_violating_process, notify_only, block_only);
    pr_info("  Logging: verbose=%d", verbose_logging);
}