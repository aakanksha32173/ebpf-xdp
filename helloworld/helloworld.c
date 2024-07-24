#include<linux/bpf.h>
#include<bpf/bpf_helpers.h>
#include<bpf/bpf_endian.h>

SEC("xdp")
int pingIP(struct xdp_md *ctx){
        bpf_printk("Hello World from ebpf xdp");
        return XDP_PASS;
}
char _license[] SEC("license")="GPL";