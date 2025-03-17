//  RootShield
//  Author: @ImKKingshuk

#include "rootshield.h"
#include "config.h"
#include "statistics.h"
#include "runtime_config.h"
#include "notification.h"

// Log security events with timestamp and severity
void log_security_event(const char *message, const char *path) {
    pr_alert("RootShield [SECURITY ALERT]: %s - %s\n", message, path);
    
    // Extract monitor type from path or message for statistics
    const char *monitor_type = "unknown";
    
    if (strstr(message, "execution") || strstr(path, "exec")) {
        monitor_type = "exec";
    } else if (strstr(message, "file") || strstr(path, "/")) {
        monitor_type = "file";
    } else if (strstr(message, "process")) {
        monitor_type = "process";
    } else if (strstr(message, "network") || strstr(path, "network")) {
        monitor_type = "network";
    } else if (strstr(message, "syscall") || strstr(path, "syscall")) {
        monitor_type = "syscall";
    } else if (strstr(message, "memory") || strstr(path, "memory")) {
        monitor_type = "memory";
    } else if (strstr(message, "module") || strstr(path, "module")) {
        monitor_type = "module";
    }
    
    // Increment violation counter
    increment_violation(monitor_type);
    
    // If verbose logging is enabled, print more details
    if (verbose_logging) {
        pr_info("RootShield: Process %s (PID: %d) triggered security alert\n", 
                current->comm, task_pid_nr(current));
    }
    
    // Send notification to userspace
    send_notification(NOTIFY_SECURITY_VIOLATION, monitor_type, message, path);
}

// Kill the current process that triggered a security violation
void kill_current_process(void) {
    struct kernel_siginfo info;
    const char *monitor_type = "unknown";
    char message[256];
    
    // Determine monitor type from current execution context
    // This is a simplified approach - in a real implementation, you'd want to pass this information
    if (current && current->comm) {
        if (strstr(current->comm, "su") || strstr(current->comm, "busybox")) {
            monitor_type = "exec";
        }
        // Add more heuristics as needed
    }
    
    // Increment blocked counter
    increment_blocked(monitor_type);
    
    // Only kill the process if configured to do so
    if (kill_violating_process && !notify_only) {
        // Send SIGKILL to the current process
        memset(&info, 0, sizeof(struct kernel_siginfo));
        info.si_signo = SIGKILL;
        info.si_code = SI_KERNEL;
        info.si_pid = task_pid_nr(current);
        
        snprintf(message, sizeof(message), "Terminating process %s (PID: %d) due to security violation", 
                 current->comm, task_pid_nr(current));
        pr_alert("RootShield: %s\n", message);
        
        // Send notification to userspace
        send_notification(NOTIFY_SECURITY_BLOCKED, monitor_type, message, current->comm);
        
        kill_pid(task_pid_vnr(current), SIGKILL, 1);
    } else if (notify_only) {
        snprintf(message, sizeof(message), "Would terminate process %s (PID: %d) but running in notify-only mode", 
                 current->comm, task_pid_nr(current));
        pr_alert("RootShield: %s\n", message);
        
        // Send notification to userspace
        send_notification(NOTIFY_SECURITY_VIOLATION, monitor_type, message, current->comm);
    } else if (block_only) {
        snprintf(message, sizeof(message), "Blocked operation by process %s (PID: %d) without termination", 
                 current->comm, task_pid_nr(current));
        pr_alert("RootShield: %s\n", message);
        
        // Send notification to userspace
        send_notification(NOTIFY_SECURITY_BLOCKED, monitor_type, message, current->comm);
    }
}