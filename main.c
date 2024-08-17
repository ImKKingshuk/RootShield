//  RootShield
//  Author: @ImKKingshuk

#include "rootshield.h"

void print_banner(void) {
    const char *banner[] = {
        "***************************************************",
        "*                     RootShield                  *",
        "*  The Ultimate Shield for Rooted Android Device  *",
        "*                       v1.1.0                    *",
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

    if (register_exec_monitor() < 0) {
        pr_err("Failed to register exec monitor");
        return -1;
    }

    if (register_file_monitor() < 0) {
        pr_err("Failed to register file monitor");
        unregister_exec_monitor();
        return -1;
    }

    if (register_process_monitor() < 0) {
        pr_err("Failed to register process monitor");
        unregister_exec_monitor();
        unregister_file_monitor();
        return -1;
    }

    pr_info("RootShield initialized successfully");
    return 0;
}

static void __exit root_shield_exit(void) {
    unregister_exec_monitor();
    unregister_file_monitor();
    unregister_process_monitor();
    pr_info("RootShield exiting");
}

module_init(root_shield_init);
module_exit(root_shield_exit);

MODULE_LICENSE("GPL-3.0");
MODULE_AUTHOR("@ImKKingshuk");
MODULE_DESCRIPTION("The Ultimate Shield for Rooted Android Devices");