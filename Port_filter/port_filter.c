#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("xdp")
int port_80_filter(struct xdp_md *ctx) {
    // Load the data from the packet
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check if there's enough space for Ethernet and IP headers
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    // Load Ethernet header
    struct ethhdr *eth = data;

    // Check if the packet is IP
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    // Load IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);

    // Check if the packet is TCP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Load TCP header
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    // Check if the destination port is 80
    if (htons(tcp->dest) == 80) {
        // Packet matches port 80
        // Drop the packet
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
