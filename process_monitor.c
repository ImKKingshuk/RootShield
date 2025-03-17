//  RootShield
//  Author: @ImKKingshuk

#include "rootshield.h"

// List of protected system paths
static const char *protected_system_paths[] = {
    "/system/",
    "/vendor/",
    "/apex/",
    "/etc/",
    "/init",
    "/sbin/"
};

static const int num_protected_system_paths = sizeof(protected_system_paths) / sizeof(char*);

// Monitor file deletion attempts
static int handler_pre_do_unlinkat(struct kprobe *p, struct pt_regs *regs) {
    struct file *f = fget((int)regs->di);
    char buf[PATH_MAX];
    char *path;
    int i;

    if (current->cred->uid.val != 0) {
        return 0;
    }

    if (!f) {
        return 0;
    }

    path = d_path(&f->f_path, buf, sizeof(buf));

    if (IS_ERR(path)) {
        fput(f);
        return 0;
    }

    // Check against all protected system paths
    for (i = 0; i < num_protected_system_paths; i++) {
        if (strstr(path, protected_system_paths[i])) {
            char message[128];
            snprintf(message, sizeof(message), "Blocked unlink operation on protected path: %s", path);
            log_security_event(message, path);
            kill_current_process();
            fput(f);
            return 0;
        }
    }

    fput(f);
    return 0;
}

// Monitor process creation
static int handler_pre_do_fork(struct kprobe *p, struct pt_regs *regs) {
    // Check for suspicious process creation patterns
    // For example, if a known malicious process is trying to fork
    if (strstr(current->comm, "suspicious") || strstr(current->comm, "malware")) {
        char message[128];
        snprintf(message, sizeof(message), "Blocked suspicious process fork: %s", current->comm);
        log_security_event(message, "process");
        kill_current_process();
        return 0;
    }
    
    return 0;
}

// Monitor process memory access (potential for code injection)
static int handler_pre_ptrace(struct kprobe *p, struct pt_regs *regs) {
    long request = regs->di;
    pid_t pid = regs->si;
    
    // Only allow certain ptrace operations
    if (request == PTRACE_POKETEXT || request == PTRACE_POKEDATA) {
        struct task_struct *task;
        char message[128];
        
        rcu_read_lock();
        task = pid_task(find_vpid(pid), PIDTYPE_PID);
        if (task) {
            snprintf(message, sizeof(message), "Blocked ptrace memory modification on PID %d by %s", 
                    pid, current->comm);
            log_security_event(message, "ptrace");
            rcu_read_unlock();
            kill_current_process();
            return 0;
        }
        rcu_read_unlock();
    }
    
    return 0;
}

static struct kprobe kp_do_unlinkat = {
    .symbol_name = "do_unlinkat",
    .pre_handler = handler_pre_do_unlinkat,
};

static struct kprobe kp_do_fork = {
    .symbol_name = "_do_fork",
    .pre_handler = handler_pre_do_fork,
};

static struct kprobe kp_ptrace = {
    .symbol_name = "ptrace_request",
    .pre_handler = handler_pre_ptrace,
};

int register_process_monitor(void) {
    int ret;
    
    ret = register_kprobe(&kp_do_unlinkat);
    if (ret < 0) {
        pr_err("RootShield: Failed to register do_unlinkat probe: %d\n", ret);
        return ret;
    }
    
    ret = register_kprobe(&kp_do_fork);
    if (ret < 0) {
        pr_err("RootShield: Failed to register do_fork probe: %d\n", ret);
        unregister_kprobe(&kp_do_unlinkat);
        return ret;
    }
    
    ret = register_kprobe(&kp_ptrace);
    if (ret < 0) {
        pr_err("RootShield: Failed to register ptrace probe: %d\n", ret);
        unregister_kprobe(&kp_do_unlinkat);
        unregister_kprobe(&kp_do_fork);
        return ret;
    }
    
    pr_info("RootShield: Process monitoring initialized\n");
    return 0;
}

void unregister_process_monitor(void) {
    unregister_kprobe(&kp_do_unlinkat);
    unregister_kprobe(&kp_do_fork);
    unregister_kprobe(&kp_ptrace);
    pr_info("RootShield: Process monitoring stopped\n");
}