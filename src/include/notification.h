//  RootShield
//  Author: @ImKKingshuk

#ifndef ROOTSHIELD_NOTIFICATION_H
#define ROOTSHIELD_NOTIFICATION_H

#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>

// Netlink definitions for userspace communication
#define NETLINK_ROOTSHIELD 31  // Custom netlink protocol
#define MAX_PAYLOAD 1024       // Maximum message size

// Notification types
#define NOTIFY_SECURITY_VIOLATION 1
#define NOTIFY_SECURITY_BLOCKED   2
#define NOTIFY_STATISTICS_UPDATE  3

// Notification structure
struct rootshield_notification {
    int type;                // Notification type
    char monitor[32];        // Monitor name (exec, file, etc.)
    char message[256];       // Alert message
    char path[256];          // Path or context information
    int pid;                 // Process ID that triggered the alert
    char process_name[64];   // Process name that triggered the alert
};

// Initialize notification system
int init_notification_system(void);

// Cleanup notification system
void cleanup_notification_system(void);

// Send notification to userspace
void send_notification(int type, const char *monitor, const char *message, const char *path);

#endif /* ROOTSHIELD_NOTIFICATION_H */