//  RootShield
//  Author: @ImKKingshuk

#include "rootshield.h"
#include "config.h"

// Log security events with timestamp and severity
void log_security_event(const char *message, const char *path) {
    pr_alert("RootShield [SECURITY ALERT]: %s - %s\n", message, path);
    
    // TODO: In a future enhancement, we could add logging to a secure location
    // or implement a ring buffer for storing recent security events
}

// Kill the current process that triggered a security violation
void kill_current_process(void) {
    struct kernel_siginfo info;
    
    // Send SIGKILL to the current process
    memset(&info, 0, sizeof(struct kernel_siginfo));
    info.si_signo = SIGKILL;
    info.si_code = SI_KERNEL;
    info.si_pid = task_pid_nr(current);
    
    pr_alert("RootShield: Terminating process %s (PID: %d) due to security violation\n", 
             current->comm, task_pid_nr(current));
    
    kill_pid(task_pid_vnr(current), SIGKILL, 1);
}