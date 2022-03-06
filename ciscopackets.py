from scapy.all import *
import sys
from scapy.contrib.cdp import *
from scapy.contrib.ospf import *

if len(sys.argv) != 3:
    print("Usage: python3 ciscopackets.py inputfile outputfile")
    sys.exit(0)

load_contrib("cdp")
load_contrib("dtp")
load_contrib("vtp")
load_contrib("vqp")
load_contrib("ospf")
load_contrib("eigrp")

pcap = rdpcap(sys.argv[1])
outputfile=sys.argv[2]


def write(pkt):
    wrpcap(outputfile, pkt, append=True)

for pkt in pcap:
    #print(pkt.show())
    if pkt.haslayer("Cisco Discovery Protocol version 2"):
        write(pkt)
    elif pkt.haslayer("VTP"):
        write(pkt)
    elif pkt.haslayer("DTP"):
        write(pkt)
    elif pkt.haslayer("VQP"):
        write(pkt)
    elif pkt.haslayer(OSPF_Hdr):
        write(pkt)
    elif pkt.haslayer("EIGRP"):
        write(pkt)
    elif pkt.haslayer(STP):
        write(pkt)
    else:
        pass

print("Finished, the results are here:"+outputfile)
