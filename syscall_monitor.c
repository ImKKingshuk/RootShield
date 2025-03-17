//  RootShield
//  Author: @ImKKingshuk

#include "rootshield.h"
#include <linux/syscalls.h>

// List of sensitive syscalls to monitor
static const char *sensitive_syscalls[] = {
    "sys_ptrace",       // Used for process tracing, can be abused
    "sys_capset",      // Used to set process capabilities
    "sys_prctl",       // Process control, can be used for various security bypasses
    "sys_mount",       // Mounting filesystems, potential for rootkit installation
    "sys_init_module", // Loading kernel modules
    "sys_finit_module" // Loading kernel modules (newer method)
};

static const int num_sensitive_syscalls = sizeof(sensitive_syscalls) / sizeof(char*);

// Array to store kprobe handlers for each syscall
static struct kprobe *syscall_kprobes;

// Generic pre-handler for sensitive syscalls
static int handler_pre_syscall(struct kprobe *p, struct pt_regs *regs) {
    // Only monitor root processes
    if (current->cred->uid.val != 0) {
        return 0;
    }
    
    // Check if this is a suspicious context (e.g., from an app that shouldn't have root)
    // This is a simplified check - in a real implementation, you'd want more sophisticated detection
    if (strstr(current->comm, "suspicious") || strstr(current->comm, "malware")) {
        char message[128];
        snprintf(message, sizeof(message), "Blocked suspicious syscall %s from process %s", 
                p->symbol_name, current->comm);
        log_security_event(message, "syscall");
        kill_current_process();
        return 0;
    }
    
    return 0;
}

int register_syscall_monitor(void) {
    int i, ret = 0;
    
    // Allocate memory for kprobe structures
    syscall_kprobes = kzalloc(sizeof(struct kprobe) * num_sensitive_syscalls, GFP_KERNEL);
    if (!syscall_kprobes) {
        pr_err("RootShield: Failed to allocate memory for syscall kprobes\n");
        return -ENOMEM;
    }
    
    // Register kprobes for each sensitive syscall
    for (i = 0; i < num_sensitive_syscalls; i++) {
        syscall_kprobes[i].symbol_name = sensitive_syscalls[i];
        syscall_kprobes[i].pre_handler = handler_pre_syscall;
        
        ret = register_kprobe(&syscall_kprobes[i]);
        if (ret < 0) {
            pr_warn("RootShield: Failed to register probe for %s (error %d)\n", 
                   sensitive_syscalls[i], ret);
            // Continue with other syscalls even if one fails
            continue;
        }
        
        pr_info("RootShield: Monitoring syscall %s\n", sensitive_syscalls[i]);
    }
    
    return 0; // Return success even if some probes failed to register
}

void unregister_syscall_monitor(void) {
    int i;
    
    if (!syscall_kprobes) {
        return;
    }
    
    // Unregister all kprobes
    for (i = 0; i < num_sensitive_syscalls; i++) {
        if (syscall_kprobes[i].symbol_name) {
            unregister_kprobe(&syscall_kprobes[i]);
        }
    }
    
    // Free allocated memory
    kfree(syscall_kprobes);
    syscall_kprobes = NULL;
}