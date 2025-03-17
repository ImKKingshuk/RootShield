//  RootShield
//  Author: @ImKKingshuk

#include "../include/rootshield.h"
#include "../include/notification.h"
#include "../include/runtime_config.h"

// Netlink socket for communication with userspace
static struct sock *nl_sock = NULL;

// Initialize the notification system
int init_notification_system(void) {
    struct netlink_kernel_cfg cfg = {
        .input = NULL, // We don't need to receive messages from userspace
    };
    
    // Create netlink socket
    nl_sock = netlink_kernel_create(&init_net, NETLINK_ROOTSHIELD, &cfg);
    if (!nl_sock) {
        pr_err("RootShield: Error creating netlink socket\n");
        return -ENOMEM;
    }
    
    pr_info("RootShield: Notification system initialized\n");
    return 0;
}

// Cleanup the notification system
void cleanup_notification_system(void) {
    if (nl_sock) {
        netlink_kernel_release(nl_sock);
        nl_sock = NULL;
    }
    pr_info("RootShield: Notification system cleaned up\n");
}

// Maximum retries for sending notifications
#define MAX_SEND_RETRIES 3
#define RETRY_DELAY_MS 100

// Send notification to userspace with retry mechanism
void send_notification(int type, const char *monitor, const char *message, const char *path) {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    struct rootshield_notification notification;
    int res, retries = 0;
    
    // Check if notification system is enabled and initialized
    if (!nl_sock) {
        pr_err("RootShield: Notification system not initialized\n");
        return;
    }
    
    // Prepare notification data
    memset(&notification, 0, sizeof(notification));
    notification.type = type;
    strncpy(notification.monitor, monitor, sizeof(notification.monitor) - 1);
    strncpy(notification.message, message, sizeof(notification.message) - 1);
    strncpy(notification.path, path, sizeof(notification.path) - 1);
    notification.pid = task_pid_nr(current);
    strncpy(notification.process_name, current->comm, sizeof(notification.process_name) - 1);
    
    // Allocate a new sk_buff with extra room for netlink header
    skb = nlmsg_new(sizeof(notification), GFP_ATOMIC);
    if (!skb) {
        pr_err("RootShield: Failed to allocate new skb\n");
        return;
    }
    
    // Add netlink header to the socket buffer
    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, sizeof(notification), 0);
    if (!nlh) {
        pr_err("RootShield: Failed to put nlmsghdr\n");
        kfree_skb(skb);
        return;
    }
    
    // Copy notification data to the socket buffer
    memcpy(nlmsg_data(nlh), &notification, sizeof(notification));
    
    // Send the message to all listeners (multicast)
    res = nlmsg_multicast(nl_sock, skb, 0, NETLINK_ROOTSHIELD, GFP_ATOMIC);
    if (res < 0 && res != -ESRCH) { // ESRCH means no process is listening, which is OK
        pr_err("RootShield: Failed to send netlink message: %d\n", res);
    }
}