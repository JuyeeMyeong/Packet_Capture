import dpkt
import socket
from functools import reduce
import binascii

f = open('filenamehere.pcap', 'rb')
pcap = dpkt.pcap.Reader(f).readpkts()

def sep_string (addr):
    s = []
    for i in range(12//2):
        s.append(addr[i*2:i*2+2].decode('utf-8'))
    res_string = ":".join(s)
    return res_string

arp_pktInfo = {"No." : 0, "Time" : 0.0, "Source": "", "Destination" : "", "Protocol" : "ARP", "Length" : 0}
pkt_num = 0
res = []
first_frame = float(pcap[0][0]) 

for packet in pcap:
    pkt_num += 1
    arp_pktInfo["No."] = pkt_num
    e = dpkt.ethernet.Ethernet(packet[1])
    ip = e.data
    
    if e.type == dpkt.ethernet.ETH_TYPE_ARP:
        arp = e.arp
        ts = packet[0]
        
        s_mac = sep_string(binascii.hexlify(e.src))
        d_mac = sep_string(binascii.hexlify(e.dst))
        arp_pktInfo["Length"] = len(e)

        src_ptc = socket.inet_ntoa(arp.spa)
        src_hrd = sep_string(binascii.hexlify(arp.sha))
        arp_pktInfo["Source"] = src_hrd
        
        trg_ptc = socket.inet_ntoa(arp.tpa)
        trg_hrd = sep_string(binascii.hexlify(arp.tha))
        arp_pktInfo["Destination"] = trg_hrd
        arp_pktInfo["Time"] = str(float(ts)  - first_frame)

        #IP address for request or reply
        if arp.op == 1:
            
            print("{\'No.\':", arp_pktInfo["No."], ", \'Time\':", arp_pktInfo["Time"],", \'Protocol\':", arp_pktInfo["Protocol"],", \'Length\':", arp_pktInfo["Length"], "}")
            print("Source Protocol:", src_ptc)
            print("Destination Protocol:", trg_ptc)
            print ("Gratuitous ARP for", socket.inet_ntoa(arp.spa), "(Request)")
        elif arp.op == 2:
            print(arp_pktInfo)
            print("Source Protocol:", src_ptc)
            print("Destination Protocol:", trg_ptc)
            print (socket.inet_ntoa(arp.spa), "is at", arp_pktInfo["Source"])
        else:
            print ("Value Unexpected")
        print("\n")
