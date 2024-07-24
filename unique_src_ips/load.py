from bcc import BPF 
from bcc.utils import printb
import socket 
import struct
import csv
file = open('file1.xlsx', 'w')
file = csv.writer(file)

device = "enp11s0f1" 
b = BPF(src_file="ippackets.c") 
fn = b.load_func("ip_source_counter", BPF.XDP) 
b.attach_(device, fn, 0) 

try:
    b.trace_print() 
except KeyboardInterrupt: 
    print("IP ADDRESS \t VALUE")
    dist = b.get_table("counter_table") 
    for k, v in (dist.items()): 
        ans=k.value
        value=v.value
        ip_bytes = struct.pack("<I", ans)
        ip_address = socket.inet_ntoa(ip_bytes)
        file.writerow([ip_address,value])
        print(ip_address,end="\t")
        print(value)
      

b.remove_xdp(device, 0) 