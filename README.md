# Packet_Capture

### **This program is an implementation of ARP packet capture using Python**

_**What is Address Resolution Protocol (ARP) ?:**_

Address Resolution Protocol (ARP) is a protocol or procedure that connects an Internet Protocol (IP) address to a fixed physical machine address, also known as a Media Access Control (MAC) address or the data link layer, which establishes and terminates a connection between two physically connected devices, in a Local-Area Network (LAN).



![Image](https://user-images.githubusercontent.com/93340211/203471487-4b5d69a4-847a-4c2a-88a9-4c59a6aa3e1a.png)



This mapping procedure is important because the lengths of the IP and MAC addresses differ, and a translation is needed so that the systems can recognize one another. The most used IP today is IP version 4 (IPv4). An IP address is 32 bits long. However, MAC addresses are 48 bits long. ARP translates the 32-bit address to 48 and vice versa.


_**Program Features:**_
This program analyzes the pcap trace for the ARP packet.Perform a byte-level programming to read each byte and convert it to the ARP header element. 

- Read Pcap file using dpkt module
- Analyze ARP packets
- Print the entire ARP request and response for one ARP packet exchange (similar to WireShark)
- Based on the ARP messages, print IP address and MAC address of the router.


_**Code Explanations:**_

1. 
