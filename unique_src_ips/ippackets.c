#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

BPF_HASH(counter_table);

int ip_source_counter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    u64 counter=0;
    u64 *p;
    if ((void *)eth + sizeof(*eth) <= data_end)
    {  
        if(bpf_ntohs(eth->h_proto)==ETH_P_IP)
        {
            struct iphdr *ip = data + sizeof(*eth);
            if ((void *)ip + sizeof(*ip) <= data_end)
            {
                        u64 value = ip->saddr;
                        p=counter_table.lookup(&value);
                        if(p!=NULL)
                            counter=*p;
                        counter++;
                        counter_table.update(&value,&counter);
            }
        }
    }
    
    return XDP_PASS;
}
