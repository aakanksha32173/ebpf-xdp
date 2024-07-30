from bcc import BPF
import ctypes


# Define the eBPF program
bpf_text = """
/*#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>*/

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/bpf_common.h>


#define DNS_PORT 5353


struct dns_header {
    __be16 id;           // Identification
    __be16 flags;        // Flags
    __be16 qdcount;      // Number of questions
    __be16 ancount;      // Number of answer resource records
    __be16 nscount;      // Number of authority resource records
    __be16 arcount;      // Number of additional resource records
};


static u64 counter = 0; 
BPF_HASH(dns_map, u64, struct dns_header);

int dns_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check if there's enough space for Ethernet and IP headers
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    // Load Ethernet header
    struct ethhdr *eth = data;

    // Check if the packet is IP
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Load IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // Check if there's enough space for UDP header
    if ((void *)(ip + 1) + sizeof(struct udphdr) > data_end)
        return XDP_PASS;

    // Check if the packet is UDP
    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if (ip->protocol == IPPROTO_UDP && udp->dest == bpf_htons(DNS_PORT)) {
        // Check if there's enough space for DNS header
        if ((void *)(udp + 1) + sizeof(struct dns_header) > data_end)
            return XDP_PASS;

        // Load DNS header
        struct dns_header *dns_hdr = (struct dns_header *)(udp + 1);
        struct dns_header dd={
            .id= bpf_ntohs(dns_hdr->id),
            .flags= bpf_ntohs(dns_hdr->flags),
            .qdcount=bpf_ntohs(dns_hdr->qdcount),
            .ancount=bpf_ntohs(dns_hdr->ancount),
            .nscount=bpf_ntohs(dns_hdr->nscount),
            .arcount=bpf_ntohs(dns_hdr->arcount),
        };
        

         u64 key = bpf_ktime_get_ns();
         dns_map.update(&key, &dd);
        
        
    }

    return XDP_PASS;
   
}
"""

# Define a ctypes structure to match the data_t struct in the eBPF program
class Data(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint16),
        ("flags", ctypes.c_uint16),
        ("qdcount", ctypes.c_uint16),
        ("ancount", ctypes.c_uint16),
        ("nscount", ctypes.c_uint16),
        ("arcount", ctypes.c_uint16)
    ]

device="enp11s0f1"
b = BPF(text=bpf_text)
fn = b.load_func("dns_prog", BPF.XDP)
b.attach_xdp("enp11s0f1", fn=fn)

print("Tracing... Hit Ctrl-C to end.")
f = open("dns.txt", "w")

try:
    while True:
        
        dns_map = b.get_table("dns_map")
        for key, leaf in dns_map.items():
            print(type(leaf))
            val=key.value
            data = ctypes.cast(ctypes.addressof(leaf), ctypes.POINTER(Data)).contents
            id=data.id
            flag=data.flags
            qdcount=data.qdcount
            ancount=data.ancount
            nscount=data.nscount
            arcount=data.arcount
            
            f.write(f"ID {id}\tflag {flag}\tqdcount {data.qdcount}\tancount {ancount}\t nscount {nscount}\t arcount {arcount} \n")
            
        dns_map.clear()

except KeyboardInterrupt:
    pass
f.close()
# Detach the program
b.remove_xdp(device, flags=0)