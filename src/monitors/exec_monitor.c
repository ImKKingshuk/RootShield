//  RootShield
//  Author: @ImKKingshuk

#include "rootshield.h"
#include "config.h"

// List of suspicious binaries to monitor
static const char *suspicious_binaries[] = {
    "/sbin/su",
    "/system/bin/su",
    "/system/xbin/su",
    "/system/bin/busybox",
    "/data/local/tmp/busybox",
    "/system/xbin/tcpdump",
    "/system/bin/strace",
    "/system/xbin/strace",
    "/data/local/tmp/frida",
    "/data/local/tmp/frida-server"
};

static const int num_suspicious_binaries = sizeof(suspicious_binaries) / sizeof(char*);

// List of suspicious commands to monitor
static const char *suspicious_commands[] = {
    "mount",
    "dd",
    "insmod",
    "modprobe",
    "ncat",
    "nc",
    "netcat",
    "tcpdump",
    "wireshark",
    "tshark"
};

static const int num_suspicious_commands = sizeof(suspicious_commands) / sizeof(char*);

static int handler_pre_execve(struct kprobe *p, struct pt_regs *regs) {
    struct filename *filename = (struct filename *)regs->di;
    const char *path;
    const char *cmd;
    int i;

    if (IS_ERR(filename)) {
        return 0;
    }

    path = filename->name;
    cmd = strrchr(path, '/');
    if (cmd) {
        cmd++; // Skip the '/' character
    } else {
        cmd = path; // No '/' in the path
    }

    // Check against suspicious binaries
    for (i = 0; i < num_suspicious_binaries; i++) {
        if (strcmp(path, suspicious_binaries[i]) == 0) {
            char message[128];
            snprintf(message, sizeof(message), "Blocked execution of suspicious binary: %s", path);
            log_security_event(message, path);
            kill_current_process();
            return 0;
        }
    }

    // Check against suspicious commands
    for (i = 0; i < num_suspicious_commands; i++) {
        if (strcmp(cmd, suspicious_commands[i]) == 0) {
            char message[128];
            snprintf(message, sizeof(message), "Blocked execution of suspicious command: %s", cmd);
            log_security_event(message, path);
            kill_current_process();
            return 0;
        }
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