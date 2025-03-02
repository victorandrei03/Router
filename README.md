# Tema1_321CC_Preda_Victor-Andrei

## IPv4 Implementation

For the implementation of the IPv4 protocol, I first check if the Ethernet type is `0x0800` (IPv4). If it is, I retrieve the IP header located at the address of the received packet plus the size of the Ethernet structure. 

- **Checksum Verification**: I verify that the checksum is equal to 0. If it is not, the packet is dropped, and I continue to the next packet.
- **TTL Verification**: I apply the same procedure for the Time-to-Live (TTL) field. If the TTL is less than or equal to 1, the packet is dropped.
- **Routing**: If the packet is valid, I search for the best route in the routing table based on the destination IP address in the IP header. If a valid route is found, I set the source MAC address, the interface through which the packet should be sent, and iterate through the cache to find the destination MAC address. If no valid route is found, the packet is dropped.

## ARP Implementation

For the ARP protocol, after finding a valid route for the packet, I search the cache for the MAC address of the destination based on the IP address of the next hop. If the MAC address is found, the steps described in the IPv4 section are applied.

- **ARP Request**: If the MAC address is not found in the cache, I create a new ARP request packet. The destination address in the ARP header is set to 6 bytes of zeros, and the destination address in the Ethernet header is set to `0xFFFFFF` for broadcast.
- **Packet Handling**: I add the IP address of the destination to an auxiliary list and add the packet to the node's packet list. After the broadcast, I expect to receive an ARP reply packet containing the MAC address. If the reply is intended for the router, I do not drop it and add the source MAC address and corresponding IP address to the cache. I then send the corresponding packets.
- **ARP Reply**: If the router intercepts an ARP request, it sends a reply packet with its own MAC address back to the sender.

## ICMP Implementation

For the ICMP protocol, after verifying that the packet is IPv4 and extracting the IP header, I check the TTL field.

- **TTL Expired**: If the TTL is less than or equal to 1, the packet is dropped, and a new ICMP packet is sent back to the sender indicating that the TTL has expired.
- **No Route Found**: If no valid route is found in the routing table, I send an ICMP "Destination Unreachable" message back to the sender.
- **ICMP Request**: If I receive an ICMP request, I check if it is intended for this router. If it is, I send an ICMP reply (type 0) back to the sender.
