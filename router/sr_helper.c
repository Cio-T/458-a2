
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_helper.h"

void makeIcmpEchoReply(uint8_t* buf, uint32_t outif_ip, int len){
	struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(buf + ETHE_SIZE);
	struct sr_icmp_hdr * icmp_hdr = (struct sr_icmp_hdr*)(buf + ETHE_SIZE + IP_SIZE);

	int size = len - ETHE_SIZE - IP_SIZE;

	ip_hdr->ip_dst = ip_hdr->ip_src;
	ip_hdr->ip_src = outif_ip; /* source and destination address */

	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_off = 0;	/* fragment offset field */
	ip_hdr->ip_id = get_ip_id(ip_hdr->ip_dst);
	ip_hdr->ip_sum = calculate_IP_checksum(ip_hdr);

	icmp_hdr->icmp_type = 0;
	icmp_hdr->icmp_code = 0;
	icmp_hdr->icmp_sum = calculate_ICMP_checksum(icmp_hdr, size);
}

uint8_t* makeIcmp(uint8_t* buf, uint32_t outif_ip, uint8_t icmp_type, uint8_t icmp_code){
	int len = LEN_ICMP;
	uint8_t* new_pac = (uint8_t *)malloc(len);

	sr_ethernet_hdr_t *ethe_header = (sr_ethernet_hdr_t *)new_pac;
	ethe_header->ether_type = htons(ethertype_ip);

	struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(new_pac + ETHE_SIZE);
	struct sr_ip_hdr *ip_hdr_buf = (struct sr_ip_hdr *)(buf + ETHE_SIZE);

   	ip_hdr->ip_dst = ip_hdr_buf->ip_src;
	ip_hdr->ip_src = outif_ip; /* source and destination address */
   	ip_hdr->ip_p = ip_protocol_icmp;	/* protocol */
   	ip_hdr->ip_hl = 5; /* header length */
	ip_hdr->ip_v = 4; /*version*/
   	ip_hdr->ip_tos = 0; /* type of service */
   	ip_hdr->ip_len = htons(len - ETHE_SIZE); /* ip data length = total length - ETHE header length*/
   	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_off = 0;	/* fragment offset field */
	ip_hdr->ip_id = get_ip_id(ip_hdr->ip_dst);
   	ip_hdr->ip_sum = calculate_IP_checksum(ip_hdr);

	struct sr_icmp_t3_hdr *icmp_hdr = (struct sr_icmp_t3_hdr*)(new_pac + ETHE_SIZE + IP_SIZE);

	icmp_hdr->icmp_type = icmp_type;
	icmp_hdr->icmp_code = icmp_code;
	memcpy(icmp_hdr->data, ip_hdr_buf, ICMP_DATA_SIZE);
	icmp_hdr->icmp_sum = calculate_ICMP_checksum((struct sr_icmp_hdr*)icmp_hdr, ICMP3_SIZE);

	free(buf);
	return new_pac;
}

int validateICMPChecksum(struct sr_icmp_hdr* icmp_hdr, int len){
    int size = len - ETHE_SIZE - IP_SIZE;
    uint16_t calc_sum = calculate_ICMP_checksum(icmp_hdr, size);
    if (icmp_hdr->icmp_sum == calc_sum){
        return 1;
    }
    printf("original ICMP sum is %d, and calculated ICMP sum is %d\n",
           icmp_hdr->icmp_sum, calc_sum);
    return 0;
}

int validateTCPChecksum(struct sr_tcp_hdr* tcp_hdr, uint16_t *ip_src_ptr, uint16_t *ip_dst_ptr,
    int size)
{
    uint16_t calc_sum = calculate_TCP_checksum(tcp_hdr, ip_src_ptr, ip_dst_ptr, size);
    if (tcp_hdr->tcp_sum == calc_sum){
        return 1;
    }
    printf("original TCP sum is %d, and calculated TCP sum is %d\n",
           tcp_hdr->tcp_sum, calc_sum);
    return 0;
}

void prepIpFwd(struct sr_ip_hdr *ip_buf){
	/*calculate the new ttl and checksum field of ip packet*/
	--ip_buf->ip_ttl;
	ip_buf->ip_sum = calculate_IP_checksum(ip_buf);
}

void prepArpReply(uint8_t *buf){
	struct sr_arp_hdr *arp_buf = (struct sr_arp_hdr *)(buf + sizeof(struct sr_ethernet_hdr));
	uint32_t tmp_ip;
	unsigned char tmp_mac[ETHER_ADDR_LEN];

	/*new dest ip = old src ip, new src ip = out interface ip*/
	tmp_ip = arp_buf->ar_tip;
	arp_buf->ar_tip = arp_buf->ar_sip;
	arp_buf->ar_sip = tmp_ip;

	/*new dest MAC = old src MAC, new src MAC = out interface MAC --for both ARP and MAC*/
	memcpy(tmp_mac, arp_buf->ar_tha, ETHER_ADDR_LEN);
	memcpy(arp_buf->ar_tha, arp_buf->ar_sha, ETHER_ADDR_LEN);
	memcpy(arp_buf->ar_sha, tmp_mac, ETHER_ADDR_LEN);
}

void prepEtheFwd(uint8_t * buf, uint8_t *dest_mac_addr, uint8_t* src_mac_addr){
	sr_ethernet_hdr_t *ethe_header = (sr_ethernet_hdr_t *)buf;

	/*change the src and dest MAC address of buf (prepare to forward)*/
	memcpy(ethe_header->ether_dhost, dest_mac_addr, ETHER_ADDR_LEN);
	memcpy(ethe_header->ether_shost, src_mac_addr, ETHER_ADDR_LEN);
}

void makeAndSendArpReq(unsigned char* dest_mac_addr, uint32_t next_hop_ip,
    struct sr_instance* sr, const char* iface){

	/*packet is alway type IP*/
	uint8_t * buf;
	int len = ETHE_SIZE + ARP_SIZE;
	buf = (uint8_t *)malloc(len); /*allocate new memory for buf*/

	struct sr_if* out_if = sr_get_interface(sr, iface);

	sr_ethernet_hdr_t *ethe_header = (sr_ethernet_hdr_t *)buf;

	/*to send an arp request*/
	prepEtheFwd(buf, dest_mac_addr, out_if->addr);
	ethe_header->ether_type = htons(ethertype_arp);

	struct sr_arp_hdr *arp_head = (struct sr_arp_hdr *)(buf + sizeof(struct sr_ethernet_hdr));

	memcpy(arp_head->ar_tha, dest_mac_addr, ETHER_ADDR_LEN);
	memcpy(arp_head->ar_sha, out_if->addr, ETHER_ADDR_LEN);

	arp_head->ar_tip = next_hop_ip;
	arp_head->ar_sip = out_if->ip;
	arp_head->ar_op = htons(arp_op_request);

	arp_head->ar_hrd = htons(arp_hrd_ethernet);
	arp_head->ar_pro = htons(ethertype_ip);
	arp_head->ar_hln = 6;
	arp_head->ar_pln = 4;

	if (sr_send_packet(sr, buf, len, iface) < 0)
		printf("Error sending ARP request.");

	free(buf);

}

