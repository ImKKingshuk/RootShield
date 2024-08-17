//  RootShield
//  Author: @ImKKingshuk

#include "rootshield.h"

static int handler_pre_do_unlinkat(struct kprobe *p, struct pt_regs *regs) {
    struct file *f = fget((int)regs->di);
    char buf[PATH_MAX];
    char *path;

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

    if (strstr(path, "/system/") || strstr(path, "/vendor/")) {
        log_security_event("Blocked unlink operation on protected path", path);
        kill_current_process();
    }

    fput(f);
    return 0;
}

static struct kprobe kp_do_unlinkat = {
    .symbol_name = "do_unlinkat",
    .pre_handler = handler_pre_do_unlinkat,
};

int register_process_monitor(void) {
    return register_kprobe(&kp_do_unlinkat);
}

void unregister_process_monitor(void) {
    unregister_kprobe(&kp_do_unlinkat);
}