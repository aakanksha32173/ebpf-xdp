#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IP_TCP 6
#define ETH_HLEN 14

struct Key {
    __u32 src_ip;               // source ip
    __u32 dst_ip;               // destination ip
    __u16 src_port;             // source port
    __u16 dst_port;             // destination port    
};

struct Leaf {
    int timestamp;              // timestamp in ns
};

struct  {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,sizeof(struct Key));
    __type(value,sizeof(struct Leaf));
    __uint(max_entries, 1024);
}sessions SEC(".maps");

SEC("xdp")
int http_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
   
    struct ethhdr *eth = data;
    if ((void *)(eth + 1)<= data_end)
    {

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_DROP;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1)<= data_end)
    {

    if (ip->protocol != IP_TCP)
        return XDP_DROP;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) <= data_end)
    {

    struct Key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };
  // Calculate payload offset and length
    __u32 ip_header_length = ip->ihl * 4;
    __u32 tcp_header_length = tcp->doff * 4;
    __u32 payload_offset = sizeof(*eth) + ip_header_length + tcp_header_length;
    __u32 payload_length = bpf_ntohs(ip->tot_len) - ip_header_length - tcp_header_length;

    if (payload_length < 7)
        return XDP_DROP;

    unsigned char *payload = data + payload_offset;

    if (payload + 7 > (unsigned char *)data_end)
        return XDP_DROP;

    // Check for HTTP methods
    if ((payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P') ||
        (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T') ||
        (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T') ||
        (payload[0] == 'P' && payload[1] == 'U' && payload[2] == 'T') ||
        (payload[0] == 'D' && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'E' && payload[4]=='T' && payload[5]=='E')||
        (payload[0] == 'H' && payload[1] == 'E' && payload[2] == 'A' && payload[3] == 'D')) {
        struct Leaf zero = {0};
        bpf_map_update_elem(&sessions, &key, &zero, BPF_ANY);
        return XDP_PASS;
    }
    }return XDP_DROP;
}return XDP_DROP;
}
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
