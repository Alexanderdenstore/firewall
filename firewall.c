#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>

/**
 * List of allowed protocols.
 */
static ushort allowed_protocol[] = {IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP};
static size_t allowed_protocol_size = sizeof(allowed_protocol) / sizeof(allowed_protocol[0]);

/**
 * List of allowed ports.
 */
static ushort allowed_ports[] = {80, 443, 22};
static size_t allowed_ports_size = sizeof(allowed_ports) / sizeof(allowed_ports[0]);


/**
 * Checks if the given protocol is allowed by comparing against 
 * the predefined list of allowed protocols.
 *
 * @param protocol The protocol number to check.
 * @return true if the protocol is allowed, false otherwise.
 */
static bool is_protocol_allowed(ushort protocol)
{
    size_t i;
    for (i = 0; i < allowed_protocol_size; i++) {
        if (allowed_protocol[i] == protocol) {
            return true;
        }
    }
    return false;
}


/**
 * Checks if the specified port is allowed by comparing against 
 * the predefined list of allowed ports.
 *
 * @param port The port number to check.
 * @return true if the port is allowed, false otherwise.
 */
static bool is_port_allowed(ushort port)
{
    size_t i;
    for (i = 0; i < allowed_ports_size; i++) {
        if (allowed_ports[i] == port) {
            return true;
        }
    }
    return false;
}


/**
 * Netfilter hook function to decide whether to accept or drop.
 * The function first checks if the packet's protocol is allowed.
 * If the packet's protocol is TCP or UDP, it then checks if the destination port 
 * is allowed.
 *
 * @param priv Pointer to private data.
 * @param skb Pointer to the sk_buff structure representing the packet.
 * @param state Information about the packet's hook state.
 * @return An action code for what to do with the packet (e.g., NF_ACCEPT, NF_DROP).
 */
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr* iph = {0};
    ushort port = 0;
    
    if (!skb) return NF_ACCEPT;

    iph = ip_hdr(skb);

    if (!is_protocol_allowed(iph->protocol))
        return NF_DROP;

    switch(iph->protocol)
    {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            if (!is_port_allowed(ntohs(iph->daddr)))
                return NF_DROP;
            break;
    }

    return NF_ACCEPT;
}


static struct nf_hook_ops nfho = {
    .hook = hook_func,
    .hooknum = NF_INET_PRE_ROUTING,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST
};


/**
 * Initialization function for the firewall module.
 * Registers the Netfilter hook function and logs module loading.
 *
 * @return 0 on successful loading of the module, non-zero on failure.
 */
static int __init firewall_init(void)
{
    nf_register_net_hook(&init_net, &nfho);

    printk(KERN_INFO "Firewall module loaded\n");
    return 0;
}


/**
 * Cleanup function for the firewall module.
 * Unregisters the Netfilter hook function and logs module unloading.
 */
static void __exit firewall_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "Firewall module unloaded\n");
}

module_init(firewall_init);
module_exit(firewall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alex");
MODULE_DESCRIPTION("Simple firewall module");