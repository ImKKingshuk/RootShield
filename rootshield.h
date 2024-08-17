//  RootShield
//  Author: @ImKKingshuk

#ifndef ROOTSHIELD_H
#define ROOTSHIELD_H

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/path.h>
#include <linux/fs.h>
#include <linux/signal.h>
#include <linux/version.h>


void print_banner(void);
void kill_current_process(void);
void log_security_event(const char *message, const char *path);


int register_exec_monitor(void);
void unregister_exec_monitor(void);


int register_file_monitor(void);
void unregister_file_monitor(void);


int register_process_monitor(void);
void unregister_process_monitor(void);

#endif /* ROOTSHIELD_H */