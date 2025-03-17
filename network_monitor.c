//  RootShield
//  Author: @ImKKingshuk

#include "rootshield.h"
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// List of suspicious ports to monitor (common backdoor ports)
static const int suspicious_ports[] = {1337, 4444, 5555, 6666, 7777, 8888, 9999};
static const int num_suspicious_ports = sizeof(suspicious_ports) / sizeof(int);

// Network hook function for outgoing packets
static unsigned int hook_outgoing_packets(void *priv, struct sk_buff *skb, 
                                        const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    int i;
    int dest_port = 0;
    
    // Skip if not root process (focus on privileged processes)
    if (current->cred->uid.val != 0) {
        return NF_ACCEPT;
    }
    
    if (!skb) {
        return NF_ACCEPT;
    }
    
    ip_header = ip_hdr(skb);
    if (!ip_header) {
        return NF_ACCEPT;
    }
    
    // Check TCP connections
    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);
        if (!tcp_header) {
            return NF_ACCEPT;
        }
        dest_port = ntohs(tcp_header->dest);
    }
    // Check UDP connections
    else if (ip_header->protocol == IPPROTO_UDP) {
        udp_header = udp_hdr(skb);
        if (!udp_header) {
            return NF_ACCEPT;
        }
        dest_port = ntohs(udp_header->dest);
    }
    
    // Check if destination port is in our suspicious list
    for (i = 0; i < num_suspicious_ports; i++) {
        if (dest_port == suspicious_ports[i]) {
            char message[128];
            snprintf(message, sizeof(message), 
                    "Blocked suspicious network connection to port %d", dest_port);
            log_security_event(message, "network");
            kill_current_process();
            return NF_DROP;
        }
    }
    
    return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
    .hook = hook_outgoing_packets,
    .hooknum = NF_INET_LOCAL_OUT,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST
};

int register_network_monitor(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    return nf_register_net_hook(&init_net, &nfho);
#else
    return nf_register_hook(&nfho);
#endif
}

void unregister_network_monitor(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_unregister_net_hook(&init_net, &nfho);
#else
    nf_unregister_hook(&nfho);
#endif
}