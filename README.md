# Packet_Capture

### **This program is an implementation of ARP packet capture using Python**

_**What is Address Resolution Protocol (ARP) ?:**_

Address Resolution Protocol (ARP) is a protocol or procedure that connects an Internet Protocol (IP) address to a fixed physical machine address, also known as a Media Access Control (MAC) address or the data link layer, which establishes and terminates a connection between two physically connected devices, in a Local-Area Network (LAN).



![Image](https://user-images.githubusercontent.com/93340211/203471487-4b5d69a4-847a-4c2a-88a9-4c59a6aa3e1a.png)



This mapping procedure is important because the lengths of the IP and MAC addresses differ, and a translation is needed so that the systems can recognize one another. The most used IP today is IP version 4 (IPv4). An IP address is 32 bits long. However, MAC addresses are 48 bits long. ARP translates the 32-bit address to 48 and vice versa.

_**What is Gratuitous ARP Packet?:**_

The frame of it is addressed to 'ff:ff:ff:ff:ff:ff' to make it a Broadcast frame.


_**Program Features:**_
This program analyzes the pcap trace for the ARP packet & Perform a byte-level programming to read each byte and convert it to the ARP header element. 

- Read Pcap file using dpkt module
- Analyze ARP packets
- Print the entire ARP request and response for one ARP packet exchange (similar to WireShark)
- Based on the ARP messages, print IP address and MAC address of the router.

_**Analyzing data packets on Wireshark:**_
- No.: The number order of the packet captured
- Time: How long after starting the capture the particular packet was captured
- Source: The address of the system that sent the packet
- Destination: The address of the packet destination
- Protocol: The type of packet (ex) TCP, UDP, or ARP
- Length: The packet's length, measured in bytes
- Info: The information about the packet contents

 -> I will utilize these when I print the analyzed data packets

_**Code Explanations:**_

- Module: dpkt (to analyze a pcap file), socket (provides the equivalent of BSD socket interface), binascii (to convert between binary and various ASCII-encoded binary representations)
- arp_pktInfo: {No., Time, Source, Destination, Protocol, Length, Info}

1. First, read packets from pcap file using dpkt (dpkt.pcap.Reader().readpkts())
2. Get the time when the first frame was captured (timestamp of the first captured packet as first_frame)
3. For each packet, check if it is an ARP packet or not.
4. If it's an ARP packet, then do the following:
 * Analyze the length of the ARP packet
 * Find the source and destination MAC address (using binascii.hexlify -> decode('utf-8') -> ":".join())
 * Find the source and destination IP address (using socket.inet_ntoa())
 * Calculate the time it was captured after the first frame was captured
 * If the packet is for reply (arp.op == 2), then print the arp_pktInfo and the IP addresses for souce and destination.
 * If the packet if for request (arp.op == 1) and the destination mac address is assigned to ffff.ffff.ffff, then print out that it is Gratuitous ARP for request.



<<---------------------------- TCP_Packet_Analysis------------------------------------>>

**This program is an implementation of TCP packet capture using Python**

_**WHat is Transmission Control Protocol?**_

The Transmission Control Protocol (TCP) determines how network devices exchange data. 
The current version of the TCP protocol allows two endpoints in a shared computer network to
establish a connection that enables a two-way transmission of data. Any data loss is detected 
and automatically corrected, which is why TCP is also called a reliable protocol. It is located at
the transport layer in the network architecture according to the OSI model. TCP protocol is
almost always based on the Internet Protocol (IP) and this connection is the foundation for
the majority of public and local networks and network services.

_**The Three-way Handshake**_

Prerequisites for establishing a valid TCP connection: Both endpoints must already have a
unique IP address (IPv4 or IPv6) and have assigned and enabled the desiredport for data transfer.
The IP address serves as an identifier, whereas the port allows the operating system to assign 
connections to be specific client and server applications.

1. The requesting clients sends the server a SYN packet or segment with a unique, random number
   and this number ensures full transmission in the correct order (without duplicates).
2. If the server has received it, it agrees to the connection by returning SYN-ACK packet including 
   the client's sequence number plus 1. It also transmits its own sequence number to the client.
3. Finally, the client acknowledges the receipt of the SYN-ACK segment by sending its own ACK packet,
   which in this case contains the server's sequence number plus 1. At the same time, the client
   can already begin transferring data to the server.
   
   <img width="732" alt="Screen Shot 2022-11-24 at 12 50 31 PM" src="https://user-images.githubusercontent.com/93340211/203689941-f40bbd71-a207-4f4e-9ec7-7cc7bbe1fbd4.png">

Following is the steps for terminating connection:

<img width="731" alt="Screen Shot 2022-11-24 at 12 52 29 PM" src="https://user-images.githubusercontent.com/93340211/203690132-7bc7260c-75ab-472c-9918-aa96725f0ee2.png">

_**Program Features:**_ This program analyzes the pcap trace for the TCP packet & perform a 
programming to read each byte and do:

1) Count the number of TCP flows initiated from the sender.
2) For each, TCP flow, for the first 2 transactions after the TCP connection is set up (from sender
   to receiver), get the values of the sequence number, ACK number, and Receive Window size.
3) Compute the sender throughput for data sent from sender to receiver
4) Compute the loss rate for each flow
5) Print the first five congestion window sizes
6) Compute the number of times a retransmission occured due to triple duplicate ack and the
   number of time a retransmission occurred due to timeout.
   

