import dpkt
import socket
from functools import reduce
import matplotlib.pyplot as plot

SRC_IP = "src_ip_address_here"
DES_IP = "dst_ip_address_here"

#Read the pcap file into a python list
f = open('file_name_here.pcap', 'rb')
pcap = dpkt.pcap.Reader(f).readpkts()

num_of_tcp_flows = 0
src_ports = {}

#Check how many SYN flags the sender transmits

for packet in pcap:
    tcp = dpkt.ethernet.Ethernet(packet[1]).data.data
    if tcp.flags == dpkt.tcp.TH_SYN:
        num_of_tcp_flows += 1
        src_ports[tcp.sport] = tcp.dport
print("The number of TCP flows initiated by the sender is", num_of_tcp_flows)

#Compute the sender throughput for data sent from sender to receiver
for src_port, des_port in src_ports.items():
    print("TCP flow between", SRC_IP, ":", src_port, "and", DES_IP, ":", des_port)

    #For the first 2 transactions after the TCP connection is set up (from sender to receiver),
    # get the values of the Sequence number, Ack number, and Receive Window size.
    
    packets_sent = {"transactions":0, "ws":0, "packets":[], "log":"Packet Sent"}
    packets_recv = {"transactions":0, "ws":0, "packets":[], "log":"Packet Received"}
    
    #Get the first 2 packets sent after set-up
    for packet in pcap:
        e = dpkt.ethernet.Ethernet(packet[1])
        ip = e.data
        if ip.data.sport == src_port and ip.data.dport == des_port and ip.data.flags == dpkt.tcp.TH_ACK:
            packets_sent["transactions"] += 1
            tcp = ip.data
            packets_sent["packets"].append(tcp)
        if ip.data.sport == src_port and ip.data.dport == des_port and ip.data.flags == dpkt.tcp.TH_SYN:
            packets_sent["ws"] = ip.data.opts[-1]
        if packets_sent["transactions"] == 2:
            break
    
    #Get the first 2 packets ACK-ed after set-up
    for packet in pcap:
        e = dpkt.ethernet.Ethernet(packet[1])
        ip = e.data
        if ip.data.dport == src_port and ip.data.sport == des_port and ip.data.flags != (dpkt.tcp.TH_SYN + dpkt.tcp.TH_ACK):
            packets_recv["transactions"] += 1
            tcp = ip.data
            packets_recv["packets"].append(tcp)
        if ip.data.dport == src_port and ip.data.sport == des_port and ip.data.flags == (dpkt.tcp.TH_SYN + dpkt.tcp.TH_ACK):
            packets_recv["ws"] = ip.data.opts[-1]
        if packets_recv["transactions"] == 2:
            break
    
    for i in (1,2):
        print("\tTransaction", i, "after setup")
        for j in [packets_sent, packets_recv]:
            print("\t\t",j["log"])
            print("\t\t\tSequence number:", j["packets"][i-1].seq)
            print("\t\t\tAck number:", j["packets"][i-1].ack)
            print("\t\t\tReceive Window size in bytes:", j["packets"][i-1].win << j["ws"])
            
#Compute the loss rate for each flow         
for src_port, des_port in src_ports.items():
    print("TCP flow between", SRC_IP, ":", src_port, "and", DES_IP, ":", des_port)
    
    #list 
    #Filter all the packets from the sender in the flow
    pcap_of_throughput = []
    
    for packet in pcap:
        e = dpkt.ethernet.Ethernet(packet[1])
        tcp = e.data.data
        if src_port == tcp.sport:
            pcap_of_throughput.append(packet)
            
    #Reduce the packet lengths to the total throughput from the sender
    total_throughput = sum(len(buf) for ts, buf in pcap_of_throughput)

    #Get the throughput duration 
    throughput_duration = pcap_of_throughput[-1][0] - pcap_of_throughput[0][0] 

    print("\tSender Throughput")
    print("\t\tNumber of packets:", len(pcap_of_throughput))
    print("\t\tThroughput in bytes:", total_throughput)
    print("\t\tThroughput duration in seconds:", round(throughput_duration, 5))
    print("\t\tThroughput in Mbits/second:", round(total_throughput * 8 / pow(10,6) / throughput_duration, 3))

#Print the first five congestion window sizes
for src_port, des_port in src_ports.items():
    print("TCP flow between", SRC_IP, ":", src_port, "and", DES_IP, ":", des_port)
    
    congestion_windows = []
    packets_sent_before_ACK = []
    window_count = 0
    ack = 0

    for packet in pcap:
        e = dpkt.ethernet.Ethernet(packet[1])
        ip = e.data
        if ip.data.sport == src_port:
            if (ip.data.flags & dpkt.tcp.TH_SYN) != 0:
                congestion_windows.append(packet)
                continue
            packets_sent_before_ACK.append(packet)
        if ip.data.dport == src_port:
            if (ip.data.flags & dpkt.tcp.TH_SYN) == 0:
                if ack == 0:
                    window_count += 1
                    congestion_windows.append(packets_sent_before_ACK[ack:])
                    ack += 2
                else:
                    window_count += 1
                    congestion_windows.append(packets_sent_before_ACK[ack:])
                    ack += 1
            continue
                    
    print("\tCongestion Windows")
    for i in range(1,6):
        print("\t\tWindow size", i, "in number of packets:", len(congestion_windows[i]))
        print("\t\t\tWindow size", i, "in bytes:", reduce( (lambda  x, y: x + len(y[1])), [0] + congestion_windows[i])) 
    
#Compute the number of times a retransmission occurred due to triple duplicate ack and the number of time a retransmission occurred due to timeout.
for src_port, des_port in src_ports.items():
    print("TCP flow between", SRC_IP, ":", src_port, "and", DES_IP, ":", des_port)
    
    time_out_retransmissions = -1 #Because the second ACK will be counted as a retransmission (e.g. SIN-0, ACK-1, ACK-1)
    retransmissions = -1 #Because the second ACK will be counted as a retransmission
    seq_numbers = {}
    
    for packet in pcap:
        e = dpkt.ethernet.Ethernet(packet[1])
        ip = e.data        
        if ip.data.sport == src_port or ip.data.dport == src_port:
            if ip.data.seq not in seq_numbers and ip.data.sport == src_port:
                seq_numbers[ip.data.seq] = 1
            elif ip.data.seq in seq_numbers and ip.data.sport == src_port:
                seq_numbers[ip.data.seq] += 1
                retransmissions += 1
                if seq_numbers[ip.data.seq] <= 3:
                    time_out_retransmissions += 1
            elif ip.data.ack in seq_numbers and ip.data.dport == src_port and ip.data.flags == dpkt.tcp.TH_ACK:
                seq_numbers[ip.data.ack] += 1
    
    
    print("\tRetransmissions:", retransmissions)
    print("\t\tDue to triple duplicate ACKS:", retransmissions - time_out_retransmissions)
    print("\t\tDue to timeouts:", time_out_retransmissions)
