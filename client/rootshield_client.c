//  RootShield Client
//  Author: @ImKKingshuk

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

// Match these with kernel definitions
#define NETLINK_ROOTSHIELD 31
#define MAX_PAYLOAD 1024

// Notification types
#define NOTIFY_SECURITY_VIOLATION 1
#define NOTIFY_SECURITY_BLOCKED   2
#define NOTIFY_STATISTICS_UPDATE  3

// Notification structure (must match kernel structure)
struct rootshield_notification {
    int type;                // Notification type
    char monitor[32];        // Monitor name (exec, file, etc.)
    char message[256];       // Alert message
    char path[256];          // Path or context information
    int pid;                 // Process ID that triggered the alert
    char process_name[64];   // Process name that triggered the alert
};

int main() {
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct msghdr msg;
    struct iovec iov;
    int sock_fd;
    
    // Create netlink socket
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROOTSHIELD);
    if (sock_fd < 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    // Initialize source address
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();  // Unique identification of the process
    
    // Bind socket
    if (bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) {
        perror("Bind failed");
        close(sock_fd);
        return -1;
    }
    
    // Initialize destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;   // For kernel
    dest_addr.nl_groups = 0; // Unicast
    
    // Allocate message buffer
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if (!nlh) {
        perror("Memory allocation failed");
        close(sock_fd);
        return -1;
    }
    
    // Fill the netlink message header
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    
    // Fill in the netlink message payload
    strcpy(NLMSG_DATA(nlh), "RootShield client started");
    
    // Initialize message
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    
    printf("RootShield Client: Waiting for notifications from kernel...");
    printf("\n(Press Ctrl+C to exit)\n\n");
    
    // Receive messages in a loop
    while (1) {
        // Receive message from kernel
        recvmsg(sock_fd, &msg, 0);
        
        // Process the notification
        struct rootshield_notification *notification = (struct rootshield_notification *)NLMSG_DATA(nlh);
        
        // Print notification details based on type
        switch (notification->type) {
            case NOTIFY_SECURITY_VIOLATION:
                printf("\033[1;31m[SECURITY VIOLATION]\033[0m %s\n", notification->message);
                break;
                
            case NOTIFY_SECURITY_BLOCKED:
                printf("\033[1;33m[SECURITY BLOCKED]\033[0m %s\n", notification->message);
                break;
                
            case NOTIFY_STATISTICS_UPDATE:
                printf("\033[1;34m[STATISTICS UPDATE]\033[0m %s\n", notification->message);
                break;
                
            default:
                printf("\033[1;37m[UNKNOWN NOTIFICATION]\033[0m %s\n", notification->message);
        }
        
        printf("  Monitor: %s\n", notification->monitor);
        printf("  Path: %s\n", notification->path);
        printf("  Process: %s (PID: %d)\n\n", notification->process_name, notification->pid);
    }
    
    // Cleanup
    close(sock_fd);
    free(nlh);
    
    return 0;
}