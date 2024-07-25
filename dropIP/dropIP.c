#include<linux/if_ether.h>
#include<linux/bpf.h>
#include<bpf/bpf_helpers.h>
#include<bpf/bpf_endian.h>
#include<arpa/inet.h>
#include<linux/ip.h>
#define ETH_P_IP 0x0800
SEC("xdp")
int dropIP(struct xdp_md *ctx){
	void* data=(void*)(long)ctx->data;
	void* data_end=(void*)(long)ctx->data_end;

	struct ethhdr *eth=data;
	if(data+sizeof(struct ethhdr)<=data_end)
	{
		if(bpf_ntohs(eth->h_proto)==ETH_P_IP)
		{
			struct iphdr *ip=data+sizeof(struct ethhdr);
			if(data+sizeof(struct ethhdr)+sizeof(struct iphdr)<=data_end)
			{
				if(bpf_ntohl(ip->saddr)==174344166){
				bpf_printk("packets dropped from ip %pI4",&ip->saddr);
				 return XDP_DROP;		
			}
			}
		}
	}
	return XDP_PASS;
}

char _license[] SEC("license")="GPL";
