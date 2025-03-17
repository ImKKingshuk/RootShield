//  RootShield
//  Author: @ImKKingshuk

#include "rootshield.h"

// List of protected paths that should not be modified
static const char *protected_paths[] = {
    "/dev/block",
    ".magisk/block",
    "/system/bin",
    "/system/xbin",
    "/system/etc/hosts",
    "/data/local/tmp",
    "/proc/sys",
    "/proc/net",
    "/proc/kallsyms",
    "/proc/modules"
};

static const int num_protected_paths = sizeof(protected_paths) / sizeof(char*);

// Monitor file write operations
static int handler_pre_vfs_write(struct kprobe *p, struct pt_regs *regs) {
    struct file *f = (struct file *)regs->di;
    char buf[256];
    char *path;
    int i;

    // Only monitor root processes
    if (current->cred->uid.val != 0) {
        return 0;
    }

    path = d_path(&f->f_path, buf, sizeof(buf));

    if (IS_ERR(path)) {
        return 0;
    }

    // Check against all protected paths
    for (i = 0; i < num_protected_paths; i++) {
        if (strstr(path, protected_paths[i])) {
            char message[128];
            snprintf(message, sizeof(message), "Blocked write to protected path: %s", path);
            log_security_event(message, path);
            kill_current_process();
            return 0;
        }
    }

    return 0;
}

// Monitor file open operations
static int handler_pre_vfs_open(struct kprobe *p, struct pt_regs *regs) {
    struct path *path_p = (struct path *)regs->di;
    char buf[256];
    char *path;
    int i;

    // Only monitor root processes
    if (current->cred->uid.val != 0) {
        return 0;
    }

    path = d_path(path_p, buf, sizeof(buf));

    if (IS_ERR(path)) {
        return 0;
    }

    // Check for suspicious file access patterns
    if (strstr(path, "/proc/kcore") || strstr(path, "/dev/kmem") || 
        strstr(path, "/dev/mem") || strstr(path, "/boot/System.map")) {
        char message[128];
        snprintf(message, sizeof(message), "Blocked access to sensitive system file: %s", path);
        log_security_event(message, path);
        kill_current_process();
        return 0;
    }

    return 0;
}

// Kprobe structures
static struct kprobe kp_vfs_write = {
    .symbol_name = "vfs_write",
    .pre_handler = handler_pre_vfs_write,
};

static struct kprobe kp_vfs_open = {
    .symbol_name = "vfs_open",
    .pre_handler = handler_pre_vfs_open,
};

int register_file_monitor(void) {
    int ret;
    
    ret = register_kprobe(&kp_vfs_write);
    if (ret < 0) {
        pr_err("RootShield: Failed to register vfs_write probe: %d\n", ret);
        return ret;
    }
    
    ret = register_kprobe(&kp_vfs_open);
    if (ret < 0) {
        pr_err("RootShield: Failed to register vfs_open probe: %d\n", ret);
        unregister_kprobe(&kp_vfs_write);
        return ret;
    }
    
    pr_info("RootShield: File monitoring initialized\n");
    return 0;
}

void unregister_file_monitor(void) {
    unregister_kprobe(&kp_vfs_write);
    unregister_kprobe(&kp_vfs_open);
    pr_info("RootShield: File monitoring stopped\n");
}