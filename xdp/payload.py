from bcc import BPF
import ctypes
import socket

# Define the eBPF program
bpf_text = """
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#define MAX_PAYLOAD_SIZE 256

struct data_t {
    u32 src_ip;
    u32 dest_ip;
    u16 src_port;
    u16 dest_port;
    u8 protocol;
    u8 payload[MAX_PAYLOAD_SIZE];
};

static u64 counter = 0; 
BPF_HASH(payload_map, u64, struct data_t);

int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip) > data_end)
            return XDP_PASS;

        struct data_t packet_data = {};
        packet_data.src_ip = ip->saddr;
        packet_data.dest_ip = ip->daddr;
        packet_data.protocol = ip->protocol;

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + sizeof(*ip);
            if ((void *)tcp + sizeof(*tcp) > data_end)
                return XDP_PASS;

            packet_data.src_port = bpf_ntohs(tcp->source);
            packet_data.dest_port = bpf_ntohs(tcp->dest);

           
            u8 *payload = (u8 *)tcp + tcp->doff*4;
            int payload_len = data_end - (void *)payload;
            if (payload_len > MAX_PAYLOAD_SIZE)
                payload_len = MAX_PAYLOAD_SIZE;
            bpf_probe_read_kernel(packet_data.payload, payload_len & MAX_PAYLOAD_SIZE,payload);

            
            u64 key = bpf_ktime_get_ns();
            payload_map.update(&key, &packet_data);

        } 
        /*else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + sizeof(*ip);
            if ((void *)udp + sizeof(*udp) > data_end)
                return XDP_PASS;

            packet_data.src_port = udp->source;
            packet_data.dest_port = udp->dest;

            
            u8 *payload = (u8 *)udp + sizeof(*udp);
            int payload_len = data_end - (void *)payload;
            if (payload_len > MAX_PAYLOAD_SIZE)
                payload_len = MAX_PAYLOAD_SIZE;
                
            bpf_probe_read_kernel(packet_data.payload, payload_len & MAX_PAYLOAD_SIZE, payload);
        
            
            u64 key = __sync_fetch_and_add(&counter, 1);
            payload_map.update(&key, &packet_data);
        }*/
    }

    return XDP_PASS;
}
"""

# Define a ctypes structure to match the data_t struct in the eBPF program
class Data(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint),
        ("dest_ip", ctypes.c_uint),
        ("src_port", ctypes.c_ushort),
        ("dest_port", ctypes.c_ushort),
        ("protocol", ctypes.c_ubyte),
        ("payload", ctypes.c_ubyte * 256)
    ]

device="enp11s0f1"
b = BPF(text=bpf_text)
fn = b.load_func("xdp_prog", BPF.XDP)
b.attach_xdp("enp11s0f1", fn=fn)

print("Tracing... Hit Ctrl-C to end.")
f = open("file2.txt", "w")

try:
    while True:
        
        payload_map = b.get_table("payload_map")
        for key, leaf in payload_map.items():
            print(type(leaf))
            val=key.value
            data = ctypes.cast(ctypes.addressof(leaf), ctypes.POINTER(Data)).contents
            src_ip = socket.inet_ntoa(data.src_ip.to_bytes(4, 'little'))
            dest_ip = socket.inet_ntoa(data.dest_ip.to_bytes(4, 'little'))
            src_port = data.src_port
            dest_port = data.dest_port
            # payload = bytes(data.payload).decode('utf-8', errors='replace')
            payload = bytes(data.payload).hex()
            f.write(f"IP {src_ip} -> {dest_ip}, Port {src_port} -> {dest_port}, Protocol {data.protocol},Payload {payload} \n")
            print("Payload:", payload)
        payload_map.clear()

except KeyboardInterrupt:
    pass
f.close()
# Detach the program
b.remove_xdp(device, flags=0)