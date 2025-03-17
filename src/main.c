//  RootShield
//  Author: @ImKKingshuk

#include "rootshield.h"

void print_banner(void) {
    const char *banner[] = {
        "***************************************************",
        "*                     RootShield                  *",
        "*  The Ultimate Shield for Rooted Android Device  *",
        "*                       v2.0.0                    *",
        "*           ----------------------------          *",
        "*                                 by @ImKKingshuk *",
        "*     Github- https://github.com/ImKKingshuk      *",
        "***************************************************"
    };

    for (int i = 0; i < sizeof(banner) / sizeof(banner[0]); i++) {
        pr_info("%s\n", banner[i]);
    }
}

static int __init root_shield_init(void) {
    print_banner();

    pr_info("RootShield initializing");

#if ENABLE_EXEC_MONITOR
    if (register_exec_monitor() < 0) {
        pr_err("Failed to register exec monitor");
        return -1;
    }
#endif

#if ENABLE_FILE_MONITOR
    if (register_file_monitor() < 0) {
        pr_err("Failed to register file monitor");
        goto cleanup_exec;
        return -1;
    }
#endif

#if ENABLE_PROCESS_MONITOR
    if (register_process_monitor() < 0) {
        pr_err("Failed to register process monitor");
        goto cleanup_file;
        return -1;
    }
#endif
    
#if ENABLE_NETWORK_MONITOR
    if (register_network_monitor() < 0) {
        pr_err("Failed to register network monitor");
        goto cleanup_process;
        return -1;
    }
#endif
    
#if ENABLE_SYSCALL_MONITOR
    if (register_syscall_monitor() < 0) {
        pr_err("Failed to register syscall monitor");
        goto cleanup_network;
        return -1;
    }
#endif

#if ENABLE_MEMORY_MONITOR
    if (register_memory_monitor() < 0) {
        pr_err("Failed to register memory monitor");
        goto cleanup_syscall;
        return -1;
    }
#endif

#if ENABLE_MODULE_MONITOR
    if (register_module_monitor() < 0) {
        pr_err("Failed to register module monitor");
        goto cleanup_memory;
        return -1;
    }
#endif

    pr_info("RootShield v%s initialized successfully", ROOTSHIELD_VERSION_STR);
    return 0;

#if ENABLE_MODULE_MONITOR
cleanup_memory:
#if ENABLE_MEMORY_MONITOR
    unregister_memory_monitor();
#endif
#endif

#if ENABLE_MEMORY_MONITOR
cleanup_syscall:
#if ENABLE_SYSCALL_MONITOR
    unregister_syscall_monitor();
#endif
#endif

#if ENABLE_SYSCALL_MONITOR
cleanup_network:
#if ENABLE_NETWORK_MONITOR
    unregister_network_monitor();
#endif
#endif

#if ENABLE_NETWORK_MONITOR
cleanup_process:
#if ENABLE_PROCESS_MONITOR
    unregister_process_monitor();
#endif
#endif

#if ENABLE_PROCESS_MONITOR
cleanup_file:
#if ENABLE_FILE_MONITOR
    unregister_file_monitor();
#endif
#endif

#if ENABLE_FILE_MONITOR
cleanup_exec:
#if ENABLE_EXEC_MONITOR
    unregister_exec_monitor();
#endif
#endif

    return -1;
}

static void __exit root_shield_exit(void) {
#if ENABLE_MODULE_MONITOR
    unregister_module_monitor();
#endif
#if ENABLE_MEMORY_MONITOR
    unregister_memory_monitor();
#endif
#if ENABLE_SYSCALL_MONITOR
    unregister_syscall_monitor();
#endif
#if ENABLE_NETWORK_MONITOR
    unregister_network_monitor();
#endif
#if ENABLE_PROCESS_MONITOR
    unregister_process_monitor();
#endif
#if ENABLE_FILE_MONITOR
    unregister_file_monitor();
#endif
#if ENABLE_EXEC_MONITOR
    unregister_exec_monitor();
#endif
    pr_info("RootShield v%s exiting", ROOTSHIELD_VERSION_STR);
}

module_init(root_shield_init);
module_exit(root_shield_exit);

MODULE_LICENSE("GPL-3.0");
MODULE_AUTHOR("@ImKKingshuk");
MODULE_DESCRIPTION("The Ultimate Shield for Rooted Android Devices");