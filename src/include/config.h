//  RootShield
//  Author: @ImKKingshuk

#ifndef ROOTSHIELD_CONFIG_H
#define ROOTSHIELD_CONFIG_H

// Version information
#define ROOTSHIELD_VERSION_MAJOR 2
#define ROOTSHIELD_VERSION_MINOR 0
#define ROOTSHIELD_VERSION_PATCH 0
#define ROOTSHIELD_VERSION_STR "2.0.0"

// Feature toggles (1 = enabled, 0 = disabled)
#define ENABLE_EXEC_MONITOR 1
#define ENABLE_FILE_MONITOR 1
#define ENABLE_PROCESS_MONITOR 1
#define ENABLE_NETWORK_MONITOR 1
#define ENABLE_SYSCALL_MONITOR 1
#define ENABLE_MEMORY_MONITOR 1
#define ENABLE_MODULE_MONITOR 1

// Logging configuration
#define MAX_LOG_ENTRIES 1000
#define LOG_TO_KERNEL_BUFFER 1
#define LOG_TO_FILE 0  // Future enhancement
#define LOG_FILE_PATH "/data/local/tmp/rootshield.log"

// Security response options
#define SECURITY_ACTION_KILL_PROCESS 1  // Kill violating process
#define SECURITY_ACTION_NOTIFY_ONLY 0   // Just log without killing
#define SECURITY_ACTION_BLOCK_ONLY 0    // Block operation without killing

// Performance settings
#define MONITOR_ROOT_PROCESSES_ONLY 1  // Only monitor processes with root privileges

#endif /* ROOTSHIELD_CONFIG_H */