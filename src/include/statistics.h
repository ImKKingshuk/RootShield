//  RootShield
//  Author: @ImKKingshuk

#ifndef ROOTSHIELD_STATISTICS_H
#define ROOTSHIELD_STATISTICS_H

#include <linux/types.h>

// Statistics structure to track security events
struct rootshield_stats {
    // Execution monitoring stats
    atomic_t exec_violations;
    atomic_t exec_blocked;
    
    // File monitoring stats
    atomic_t file_violations;
    atomic_t file_blocked;
    
    // Process monitoring stats
    atomic_t process_violations;
    atomic_t process_blocked;
    
    // Network monitoring stats
    atomic_t network_violations;
    atomic_t network_blocked;
    
    // Syscall monitoring stats
    atomic_t syscall_violations;
    atomic_t syscall_blocked;
    
    // Memory monitoring stats
    atomic_t memory_violations;
    atomic_t memory_blocked;
    
    // Module monitoring stats
    atomic_t module_violations;
    atomic_t module_blocked;
    
    // Total stats
    atomic_t total_violations;
    atomic_t total_blocked;
};

// Global statistics instance
extern struct rootshield_stats rs_stats;

// Initialize statistics
void init_statistics(void);

// Reset statistics
void reset_statistics(void);

// Print current statistics
void print_statistics(void);

// Increment violation counter for a specific monitor
void increment_violation(const char *monitor_name);

// Increment blocked counter for a specific monitor
void increment_blocked(const char *monitor_name);

#endif /* ROOTSHIELD_STATISTICS_H */