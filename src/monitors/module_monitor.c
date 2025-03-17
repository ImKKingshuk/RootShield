//  RootShield
//  Author: @ImKKingshuk

#include "rootshield.h"
#include "config.h"
#include <linux/module.h>
#include <linux/kmod.h>

// List of suspicious module names that might indicate malware
static const char *suspicious_module_names[] = {
    "hide",
    "root",
    "hack",
    "inject",
    "hook",
    "stealth",
    "cloak",
    "mask",
    "exploit"
};

static const int num_suspicious_module_names = sizeof(suspicious_module_names) / sizeof(char*);

// Monitor module loading attempts
static int handler_pre_load_module(struct kprobe *p, struct pt_regs *regs) {
    // Extract module name from parameters
    const char *module_name = (const char *)regs->di;
    int i;
    
    if (!module_name) {
        return 0;
    }
    
    // Check against suspicious module names
    for (i = 0; i < num_suspicious_module_names; i++) {
        if (strstr(module_name, suspicious_module_names[i])) {
            char message[128];
            snprintf(message, sizeof(message), 
                    "Blocked loading of suspicious kernel module: %s", 
                    module_name);
            log_security_event(message, "module");
            
#if SECURITY_ACTION_KILL_PROCESS
            kill_current_process();
#endif
            return 0;
        }
    }
    
    // Additional checks for module signature verification could be added here
    
    return 0;
}

// Kprobe structures
static struct kprobe kp_load_module = {
    .symbol_name = "load_module",
    .pre_handler = handler_pre_load_module,
};

int register_module_monitor(void) {
    int ret;
    
    ret = register_kprobe(&kp_load_module);
    if (ret < 0) {
        pr_err("RootShield: Failed to register module loading probe: %d\n", ret);
        return ret;
    }
    
    pr_info("RootShield: Module loading monitoring initialized\n");
    return 0;
}

void unregister_module_monitor(void) {
    unregister_kprobe(&kp_load_module);
    pr_info("RootShield: Module loading monitoring stopped\n");
}