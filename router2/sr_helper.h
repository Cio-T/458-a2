
#include <stdio.h>
#include "sr_protocol.h"
#include "sr_arpcache.h"

/*=helper functions =for preparing packets to send*/

void prepIpFwd(struct sr_ip_hdr*);
void prepEtheFwd(uint8_t*, uint8_t*, uint8_t*);
void prepArpReply(uint8_t*);
void makeAndSendArpReq(unsigned char* dest_mac_addr, uint32_t next_hop_ip,
	struct sr_instance* sr, const char* iface);

void makeIcmpEchoReply(uint8_t* buf, struct sr_if* out_if);

int validateICMPChecksum(struct sr_icmp_hdr* icmp_hdr, int size);
void prepICMPPacket(struct sr_icmp_hdr*, int, int, int);
void prepEtheEchoReply(uint8_t*);

/*=helper functions =for making new packets*/
void makeAndSendICMP(int len, uint8_t* packet, struct sr_instance* sr, const char* iface,
	uint8_t icmp_type, uint8_t icmp_code);
void populateICMP(struct sr_icmp_hdr* icmp_head);
void populateType3ICMP(struct sr_icmp_t3_hdr* icmp3_head);
void revIPPacket(struct sr_ip_hdr* ip_head);

void populateARP(struct sr_arp_hdr*, unsigned char*, uint32_t, unsigned char*, uint32_t);
void populateIP(struct sr_ip_hdr*, uint32_t src_ip_addr, int);

/*
enum pac_len {
  arp_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr),
  icmp_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr),
  icmp3_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr),
};
*/

enum header_length {
    ETHE_SIZE = sizeof(struct sr_ethernet_hdr),
    ARP_SIZE = sizeof(struct sr_arp_hdr),
    IP_SIZE =  sizeof(struct sr_ip_hdr),
    ICMP_SIZE = sizeof(struct sr_icmp_hdr),
    ICMP3_SIZE = sizeof(struct sr_icmp_t3_hdr),
};

enum packet_length {
    LEN_ICMP = ETHE_SIZE + IP_SIZE + ICMP3_SIZE + ICMP_DATA_SIZE,
};
