import dpkt
import socket
from functools import reduce
import binascii

f = open('filenamehere.pcap', 'rb')
#use pcap file reader to read packets
pcap = dpkt.pcap.Reader(f).readpkts()

def sep_string (addr):
    s = []
    for i in range(12//2):
        #separate the MAC address and decode it into utf-8
        s.append(addr[i*2:i*2+2].decode('utf-8'))
    #join all items into a string using ':' as a separator
    res_string = ":".join(s)
    return res_string

arp_pktInfo = {"No." : 0, "Time" : 0.0, "Source": "", "Destination" : "", "Protocol" : "ARP", "Length" : 0}
#the order number of packet
pkt_num = 0
#timestamp when the first frame was captured
first_frame = float(pcap[0][0]) 

for packet in pcap:
    #increment the order number by 1 for each packet
    pkt_num += 1
    arp_pktInfo["No."] = pkt_num
    e = dpkt.ethernet.Ethernet(packet[1])
    ip = e.data
    
    #Check whether the packet type is ARP
    if e.type == dpkt.ethernet.ETH_TYPE_ARP:
        arp = e.arp
        ts = packet[0]
        
        #Analyze MAC addresses
        #e.src / e.dst: Ethernet or other MAC address for src and dst
        s_mac = sep_string(binascii.hexlify(e.src))
        d_mac = sep_string(binascii.hexlify(e.dst))
        
        #Analyze "Length", "Source", "Destination", "Time", and IP addresses
        #length of arp packet (in bytes)
        arp_pktInfo["Length"] = len(e)
        
        #source protocol address
        src_ptc = socket.inet_ntoa(arp.spa)
        #src_hrd = sep_string(binascii.hexlify(arp.sha))
        arp_pktInfo["Source"] = s_mac
        
        #target protocol address
        trg_ptc = socket.inet_ntoa(arp.tpa)
        #trg_hrd = sep_string(binascii.hexlify(arp.tha))
        arp_pktInfo["Destination"] = d_mac
        
        #seconds since first captured packet
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
