from bcc import BPF 
from bcc.utils import printb
import socket 
import struct
import csv
import ctypes
file = open('file1.xlsx', 'w')
file = csv.writer(file)
class U64(ctypes.Structure):
    _fields_ = [("value", ctypes.c_uint64)]

device = "enp11s0f0" 
b = BPF(src_file="kernel.c") 
fn = b.load_func("ip_source_counter", BPF.XDP) 
b.attach_xdp(device, fn, BPF.XDP_FLAGS_UPDATE_IF_NOEXIST) 
# ADD IPS TO BE BLOCKED VALUE SECTION IS RANDOM HERE AND IS OF NO SIGNIFICANCE(CAN BE MODIFIED FOR TESTING PURPOSES)
ip_to_add = {
        '192.168.1.1': 10,
        '10.206.4.7': 20,
        '10.206.3.92':1,
        '224.0.0.0':2,

    }
dist = b.get_table("counter_table") 
    # Convert IP address to network byte order
for ip_str, value in ip_to_add.items():
        ip_bytes = socket.inet_aton(ip_str)  # Convert IP to bytes
        ip_int = struct.unpack("<I", ip_bytes)[0]  # Convert bytes to integer
        # Update the map
        key = U64()
        key.value = ip_int
        leaf = U64()
        leaf.value = value

        # Update the map
        dist[key] = leaf
        
try:
    b.trace_print() 
except KeyboardInterrupt: 
    print("IP ADDRESS \t VALUE")
    
    for k, v in (dist.items()): 
        ans=k.value
        value=v.value
        ip_bytes = struct.pack("<I", ans)
        ip_address = socket.inet_ntoa(ip_bytes)
        file.writerow([ip_address,value])
        print(ip_address,end="\t")
        print(value)
      
# b.remove_xdp(device,0)
 