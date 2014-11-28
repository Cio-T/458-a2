For handling incoming packets, my handle packet function first look
at its ethernet type and determine if its network protocal is IP or
ARP. The only ARP packets we need to look at are ones with ARP header 
destination IP address equal to one of the router interfaces' IP 
addresses. And then we can determine whether the ARP type is ARP request
or ARP reply, and call the ARP request/reply handler function accordingly.
On the other hand, if the ethernet packet type is IP, we can first determine
if the IP packet is valid (validate checksum, length, etc.), drop invalid 
packets, and send ICMP packets back if ttl has expired. If the IP packet is 
valid, again we need to determine whether the IP packet is addressed to self. 
If it is, the only one we need to reply is ICMP echo request (we can just
drop the rest). Else, we need to forward the IP packet, and after we take 
care of the IP header, we find the next hop ip and search for the corresponding
MAC address from the ARP cache in the router. If entry is found, we populate
the ethernet header and forward packet. Else, we call the arp request function
to insert arp request into the router's arp request queue, and send an ARP
request to the broadcast MAC address.
One ambiguity I found is that when we are sending packets (ICMP or ARP reply) to the sender,
it is not specified if we need to create a new packet and populate it with self-created 
parameters, or if we could just make a copy of the incoming packets and change
the necessary parameters accordingly. And my implementation is that if the
packet's destined ip is addressed to the router's interface, we will send back
a replica with only the necessary parameters changed. Else, we will create
a new packet to send back with all parameters self-populated.
