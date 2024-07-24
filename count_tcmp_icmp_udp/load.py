from bcc import BPF 
from bcc.utils import printb
import socket 
import struct
import csv
file = open('file1.xlsx', 'w')
file = csv.writer(file)

device = "enp11s0f1" 
b = BPF(src_file="kernel.c") 
fn = b.load_func("count_packets_of_diff_protocols", BPF.XDP) 
b.attach_xdp(device, fn, 0) 
dict={
    17:"UDP",
    6:"TCP",
    1:"ICMP"
}
try:
    b.trace_print() 
except KeyboardInterrupt: 
    print("Protocol\tNo of packets")
    dist = b.get_table("counter_table") 
    for k, v in (dist.items()): 
        ans=k.value
        value=v.value
        file.writerow([dict[ans],value])
        print(dict[ans],end="\t\t")
        print(value)
      

b.remove_xdp(device, 0) 