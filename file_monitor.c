#include "rootshield.h"

static int handler_pre_vfs_write(struct kprobe *p, struct pt_regs *regs) {
    struct file *f = (struct file *)regs->di;
    char buf[128];
    char *path;

    if (current->cred->uid.val != 0) {
        return 0;
    }

    path = d_path(&f->f_path, buf, sizeof(buf));

    if (IS_ERR(path)) {
        return 0;
    }

    if (strstr(path, "/dev/block") || strstr(path, ".magisk/block")) {
        log_security_event("Blocked write to protected path", path);
        kill_current_process();
    }

    return 0;
}

static struct kprobe kp_vfs_write = {
    .symbol_name = "vfs_write",
    .pre_handler = handler_pre_vfs_write,
};

int register_file_monitor(void) {
    return register_kprobe(&kp_vfs_write);
}

void unregister_file_monitor(void) {
    unregister_kprobe(&kp_vfs_write);
}