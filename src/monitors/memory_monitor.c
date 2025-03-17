//  RootShield
//  Author: @ImKKingshuk

#include "rootshield.h"
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/mempool.h>

// Monitor memory allocation and deallocation to detect potential memory corruption
static int handler_pre_kmalloc(struct kprobe *p, struct pt_regs *regs) {
    size_t size = regs->di;
    unsigned int flags = regs->si;
    
    // Only monitor root processes
    if (current->cred->uid.val != 0) {
        return 0;
    }
    
    // Check for suspicious large allocations that might indicate buffer overflow attempts
    if (size > 1024 * 1024 * 10) {  // 10MB threshold
        char message[128];
        snprintf(message, sizeof(message), 
                "Suspicious large memory allocation (%zu bytes) by process %s", 
                size, current->comm);
        log_security_event(message, "memory");
        
        // Depending on configuration, we might want to block or just log
#if SECURITY_ACTION_KILL_PROCESS
        kill_current_process();
#endif
        return 0;
    }
    
    return 0;
}

// Monitor page table modifications to detect potential code injection
static int handler_pre_set_memory(struct kprobe *p, struct pt_regs *regs) {
    unsigned long addr = regs->di;
    int numpages = regs->si;
    
    // Only monitor root processes
    if (current->cred->uid.val != 0) {
        return 0;
    }
    
    // Check if this is modifying executable memory
    if (p->symbol_name && strstr(p->symbol_name, "set_memory_x")) {
        char message[128];
        snprintf(message, sizeof(message), 
                "Detected attempt to make memory executable at 0x%lx by process %s", 
                addr, current->comm);
        log_security_event(message, "memory");
        
#if SECURITY_ACTION_KILL_PROCESS
        kill_current_process();
#endif
        return 0;
    }
    
    return 0;
}

// Kprobe structures
static struct kprobe kp_kmalloc = {
    .symbol_name = "__kmalloc",
    .pre_handler = handler_pre_kmalloc,
};

static struct kprobe kp_set_memory_x = {
    .symbol_name = "set_memory_x",
    .pre_handler = handler_pre_set_memory,
};

static struct kprobe kp_set_memory_rw = {
    .symbol_name = "set_memory_rw",
    .pre_handler = handler_pre_set_memory,
};

int register_memory_monitor(void) {
    int ret;
    
    ret = register_kprobe(&kp_kmalloc);
    if (ret < 0) {
        pr_err("RootShield: Failed to register kmalloc probe: %d\n", ret);
        return ret;
    }
    
    ret = register_kprobe(&kp_set_memory_x);
    if (ret < 0) {
        pr_err("RootShield: Failed to register set_memory_x probe: %d\n", ret);
        unregister_kprobe(&kp_kmalloc);
        return ret;
    }
    
    ret = register_kprobe(&kp_set_memory_rw);
    if (ret < 0) {
        pr_err("RootShield: Failed to register set_memory_rw probe: %d\n", ret);
        unregister_kprobe(&kp_kmalloc);
        unregister_kprobe(&kp_set_memory_x);
        return ret;
    }
    
    pr_info("RootShield: Memory monitoring initialized\n");
    return 0;
}

void unregister_memory_monitor(void) {
    unregister_kprobe(&kp_kmalloc);
    unregister_kprobe(&kp_set_memory_x);
    unregister_kprobe(&kp_set_memory_rw);
    pr_info("RootShield: Memory monitoring stopped\n");
}