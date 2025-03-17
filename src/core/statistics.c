//  RootShield
//  Author: @ImKKingshuk

#include "../include/rootshield.h"
#include "../include/statistics.h"

// Global statistics instance
struct rootshield_stats rs_stats;

// Threat level tracking
static atomic_t current_threat_level = ATOMIC_INIT(0);
static atomic_t max_threat_level = ATOMIC_INIT(0);

// Threat assessment thresholds
#define THREAT_LEVEL_LOW 5
#define THREAT_LEVEL_MEDIUM 15
#define THREAT_LEVEL_HIGH 30
#define THREAT_LEVEL_CRITICAL 50

// Initialize statistics
void init_statistics(void) {
    // Initialize execution monitoring stats
    atomic_set(&rs_stats.exec_violations, 0);
    atomic_set(&rs_stats.exec_blocked, 0);
    
    // Initialize file monitoring stats
    atomic_set(&rs_stats.file_violations, 0);
    atomic_set(&rs_stats.file_blocked, 0);
    
    // Initialize process monitoring stats
    atomic_set(&rs_stats.process_violations, 0);
    atomic_set(&rs_stats.process_blocked, 0);
    
    // Initialize network monitoring stats
    atomic_set(&rs_stats.network_violations, 0);
    atomic_set(&rs_stats.network_blocked, 0);
    
    // Initialize syscall monitoring stats
    atomic_set(&rs_stats.syscall_violations, 0);
    atomic_set(&rs_stats.syscall_blocked, 0);
    
    // Initialize memory monitoring stats
    atomic_set(&rs_stats.memory_violations, 0);
    atomic_set(&rs_stats.memory_blocked, 0);
    
    // Initialize module monitoring stats
    atomic_set(&rs_stats.module_violations, 0);
    atomic_set(&rs_stats.module_blocked, 0);
    
    // Initialize total stats
    atomic_set(&rs_stats.total_violations, 0);
    atomic_set(&rs_stats.total_blocked, 0);
    
    pr_info("RootShield: Statistics initialized");
}

// Reset statistics
void reset_statistics(void) {
    init_statistics();
    pr_info("RootShield: Statistics reset");
}

// Print current statistics
void print_statistics(void) {
    pr_info("RootShield Security Statistics:");
    pr_info("  Execution Monitor: %d violations, %d blocked", 
            atomic_read(&rs_stats.exec_violations), 
            atomic_read(&rs_stats.exec_blocked));
    pr_info("  File Monitor: %d violations, %d blocked", 
            atomic_read(&rs_stats.file_violations), 
            atomic_read(&rs_stats.file_blocked));
    pr_info("  Process Monitor: %d violations, %d blocked", 
            atomic_read(&rs_stats.process_violations), 
            atomic_read(&rs_stats.process_blocked));
    pr_info("  Network Monitor: %d violations, %d blocked", 
            atomic_read(&rs_stats.network_violations), 
            atomic_read(&rs_stats.network_blocked));
    pr_info("  Syscall Monitor: %d violations, %d blocked", 
            atomic_read(&rs_stats.syscall_violations), 
            atomic_read(&rs_stats.syscall_blocked));
    pr_info("  Memory Monitor: %d violations, %d blocked", 
            atomic_read(&rs_stats.memory_violations), 
            atomic_read(&rs_stats.memory_blocked));
    pr_info("  Module Monitor: %d violations, %d blocked", 
            atomic_read(&rs_stats.module_violations), 
            atomic_read(&rs_stats.module_blocked));
    pr_info("  Total: %d violations, %d blocked", 
            atomic_read(&rs_stats.total_violations), 
            atomic_read(&rs_stats.total_blocked));
}

// Increment violation counter for a specific monitor
void increment_violation(const char *monitor_name) {
    if (strcmp(monitor_name, "exec") == 0) {
        atomic_inc(&rs_stats.exec_violations);
    } else if (strcmp(monitor_name, "file") == 0) {
        atomic_inc(&rs_stats.file_violations);
    } else if (strcmp(monitor_name, "process") == 0) {
        atomic_inc(&rs_stats.process_violations);
    } else if (strcmp(monitor_name, "network") == 0) {
        atomic_inc(&rs_stats.network_violations);
    } else if (strcmp(monitor_name, "syscall") == 0) {
        atomic_inc(&rs_stats.syscall_violations);
    } else if (strcmp(monitor_name, "memory") == 0) {
        atomic_inc(&rs_stats.memory_violations);
    } else if (strcmp(monitor_name, "module") == 0) {
        atomic_inc(&rs_stats.module_violations);
    }
    
    // Increment total violations counter
    atomic_inc(&rs_stats.total_violations);
}

// Increment blocked counter for a specific monitor
void increment_blocked(const char *monitor_name) {
    if (strcmp(monitor_name, "exec") == 0) {
        atomic_inc(&rs_stats.exec_blocked);
    } else if (strcmp(monitor_name, "file") == 0) {
        atomic_inc(&rs_stats.file_blocked);
    } else if (strcmp(monitor_name, "process") == 0) {
        atomic_inc(&rs_stats.process_blocked);
    } else if (strcmp(monitor_name, "network") == 0) {
        atomic_inc(&rs_stats.network_blocked);
    } else if (strcmp(monitor_name, "syscall") == 0) {
        atomic_inc(&rs_stats.syscall_blocked);
    } else if (strcmp(monitor_name, "memory") == 0) {
        atomic_inc(&rs_stats.memory_blocked);
    } else if (strcmp(monitor_name, "module") == 0) {
        atomic_inc(&rs_stats.module_blocked);
    }
    
    // Increment total blocked counter
    atomic_inc(&rs_stats.total_blocked);
}