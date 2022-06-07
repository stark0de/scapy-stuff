from scapy.all import *
import sys
import os

myinterface=sys.argv[1]
time=sys.argv[2]

myip = os.popen('ip addr show eth0').read().split("inet ")[1].split("/")[0]

pkts=sniff(iface=myinterface,filter="udp port 53",timeout=time,store=1)

#print(pkts)

for pkt in pkts:
    #pkt.summary()
    if packet.haslayer(DNSQR):
        query = packet[DNSQR].qname
        print(query)
        if "in-addr.arpa" in query:
           if IP in pkt:
              ip_src=pkt[IP].src
              if ip_src.strip().rstrip() == myip.strip().rstrip()
                 pass
              else:
                 print("Possible sniffer found at" +str(ip_src))
