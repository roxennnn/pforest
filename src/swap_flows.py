# Loads the packets from the given .pcap files and impose source/destination IP addresses and transport protocol ports.
# The purpose of this file is to unify backward and forward flows in a single one.

from scapy.all import *
from scapy.utils import rdpcap
from os import listdir

src_path = "old_pcap/datasets_for_adv-net_pforest/"
dst_path = "pcap/"

for filename in listdir(src_path):
    print()
    print(filename)
    pkts = rdpcap(src_path + filename)
    srcAddr = ""
    dstAddr = ""
    srcPort = 0
    dstPort = 0
    for i,pkt in enumerate(pkts):
        if i == 0:
            srcAddr = pkt[IP].src
            dstAddr = pkt[IP].dst
            srcPort = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
            dstPort = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
        else:
            pkt[IP].src = srcAddr
            pkt[IP].dst = dstAddr
            if TCP in pkt:
                pkt[TCP].sport = srcPort
                pkt[TCP].dport = dstPort
            else:
                pkt[UDP].sport = srcPort
                pkt[UDP].dport = dstPort

        wrpcap(dst_path+filename, pkt, append=True)