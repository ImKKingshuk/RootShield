//  RootShield
//  Author: @ImKKingshuk

#include "rootshield.h"

static int handler_pre_execve(struct kprobe *p, struct pt_regs *regs) {
    struct filename *filename = (struct filename *)regs->di;
    char buf[64];
    const char *path;

    if (IS_ERR(filename)) {
        return 0;
    }

    path = filename->name;

    if (strcmp(path, "/sbin/su") == 0 || strcmp(path, "/system/bin/su") == 0) {
        log_security_event("Blocked execution of su binary", path);
        kill_current_process();
        return 0;
    }

    return 0;
}

static struct kprobe kp_execve = {
    .symbol_name = "do_execveat_common",
    .pre_handler = handler_pre_execve,
};

int register_exec_monitor(void) {
    return register_kprobe(&kp_execve);
}

void unregister_exec_monitor(void) {
    unregister_kprobe(&kp_execve);
}