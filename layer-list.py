from scapy.all import *
import sys

filename = sys.argv[1]

scapycapture = rdpcap(filename)

x=1

for packet in scapycapture:
    print("Packet number "+str(x)+":")
    for i in packet.payload.layers():
        print(str(i).split(".")[int(len(str(i).split("."))-1)].split("'>")[0],end='')
        if len(packet.payload.layers()) - 1 == packet.payload.layers().index(i):
            print()
            pass
        else:
            print(",",end="")
    x+=1
