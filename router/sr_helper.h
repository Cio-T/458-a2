
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
uint8_t* makeIcmp(uint8_t* buf, struct sr_if* out_if, uint8_t icmp_type, uint8_t icmp_code);

int validateICMPChecksum(struct sr_icmp_hdr* icmp_hdr, int size);
int validateTCPChecksum(struct sr_tcp_hdr * tcp_buf, int size)

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
    ICMP_ECHO_SIZE = sizeof(struct sr_icmp_echo_hdr),
    ICMP3_SIZE = sizeof(struct sr_icmp_t3_hdr),
    TCP_SIZE = sizeof(struct sr_tcp_hdr),
};

enum packet_length {
    LEN_ICMP = ETHE_SIZE + IP_SIZE + ICMP3_SIZE,
};
