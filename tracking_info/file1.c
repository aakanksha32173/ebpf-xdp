#include<linux/bpf.h>
#include<bpf/bpf_helpers.h>
#include<linux/if_ether.h>
#include<linux/ip.h>
#include<arpa/inet.h>
#include<bpf/bpf_endian.h>
#define ETH_P_IP 0x0800
SEC("xdp")
int pingIP(struct xdp_md *ctx){

	void* data=(void*)(long)ctx->data;
	void* data_end=(void*)(long)ctx->data_end;

	struct ethhdr *eth=data;
	if(data + sizeof(struct ethhdr)>data_end)
		return XDP_PASS;

	if(bpf_ntohs(eth->h_proto)==ETH_P_IP)
	{

	struct iphdr *ip=data + sizeof(struct ethhdr);
	if(data + sizeof(struct ethhdr)+ sizeof(struct iphdr)<=data_end){
	bpf_printk("proto%u",ip->protocol);
	bpf_printk("ping packet from ip %pI4",&ip->saddr);
	bpf_printk("ping packet to ip %pI4", &ip->daddr);

}}

	return XDP_PASS;
}
char _license[] SEC("license")="GPL";
