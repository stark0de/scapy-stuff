# scapy-stuff
Random scapy scripts for various tasks

## layer-list

Usage: python3 layer-list.py routetoPCAPfile

This script just prints out the layers of each packet in the PCAP file you supply as argument

## ciscopackets

Usage: python3 ciscopackets.py input.pcap output.pcap

This script just reads a given PCAP file and writes all the packets from some of Cisco's propietary protocols to an output file. This could be useful for internal pentests/red team engagements to check if you are in a environment which uses Cisco products.
