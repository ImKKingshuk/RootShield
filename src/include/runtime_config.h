//  RootShield
//  Author: @ImKKingshuk

#ifndef ROOTSHIELD_RUNTIME_CONFIG_H
#define ROOTSHIELD_RUNTIME_CONFIG_H

#include <linux/module.h>
#include <linux/moduleparam.h>

// Runtime configuration parameters
// These can be modified when loading the module with insmod

// Enable/disable specific monitors at runtime
extern bool exec_monitor_enabled;
extern bool file_monitor_enabled;
extern bool process_monitor_enabled;
extern bool network_monitor_enabled;
extern bool syscall_monitor_enabled;
extern bool memory_monitor_enabled;
extern bool module_monitor_enabled;

// Security response configuration
extern bool kill_violating_process;
extern bool notify_only;
extern bool block_only;

// Logging configuration
extern bool verbose_logging;

// Initialize runtime configuration
void init_runtime_config(void);

// Apply runtime configuration
void apply_runtime_config(void);

// Print current configuration
void print_runtime_config(void);

#endif /* ROOTSHIELD_RUNTIME_CONFIG_H */