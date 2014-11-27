
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


int validIPPacket(struct sr_ip_hdr *ip_buf){
    uint16_t calc_sum = calculate_IP_checksum(ip_buf);

    if (ip_buf->ip_v != 4) {
        printf("IP version is not 4\n");
        return 0;
    }
    if (ip_buf->ip_hl < 4) {
        printf("IP header length is %d\n", ip_buf->ip_hl);
        return 0;
    }
    if (ntohl(ip_buf->ip_len) < 5) {
        printf("ERROR: Total length is less than IP header length + UDP header length");
        return 0;
    }
    if (ip_buf->ip_sum != calc_sum){
        /*Drop packet*/
        printf("ERROR: checksum_ip=%d, checksum_calc = %d\n", ip_buf->ip_sum, calc_sum);
        return 0;
    }
    return 1;
}

struct sr_rt* getBestRtEntry(struct sr_rt* routing_table, struct sr_ip_hdr *ip_buf){
    struct sr_rt* best_rt_entry = (struct sr_rt*)NULL;
    struct sr_rt* rt_walker = routing_table;
    int longest_prefix_count = 0;
    int count = 32;
    uint32_t cmp_dest, cmp_entry;
	cmp_dest = ip_buf->ip_dst;

    /*find longest prefix match entry in routing table*/
    while (rt_walker && longest_prefix_count < 32){
        /*find longest bit match length*/
        cmp_entry = rt_walker->dest.s_addr & rt_walker->mask.s_addr;
        while (count > longest_prefix_count){
            if ((cmp_entry ^ cmp_dest) == 0){
                longest_prefix_count = count;
                best_rt_entry = rt_walker;
            } else {
                cmp_dest = cmp_dest >> 1;
                cmp_entry = cmp_entry >> 1;
                --count;
            }
        }
        rt_walker = rt_walker->next;
        count = 32;
    }
    return best_rt_entry;
}

int packetIsToSelf(struct sr_instance* sr, uint8_t *buf, int isIP, char* if_name){
	unsigned char *tmp_ptr;
	struct sr_if* get_if;

	if (isIP){
        struct sr_ip_hdr *ip_buf = (struct sr_ip_hdr *)(buf + sizeof(struct sr_ethernet_hdr));
		get_if = sr->if_list;
		while(get_if) {
			if (ntohl(ip_buf->ip_dst) == ntohl(get_if->ip)){
				printf("is ip packet to self\n");
				return 1;
			}else{
				get_if = get_if->next;
			}
		}
	} else{
        struct sr_arp_hdr *arp_buf = (struct sr_arp_hdr *)(buf + sizeof(struct sr_ethernet_hdr));
		get_if = sr_get_interface(sr, if_name);
		if (arp_buf->ar_tip == get_if->ip){
			if (ntohs(arp_buf->ar_op) == arp_op_request){/*If the ARP packet is ARP request*/
				tmp_ptr = get_if->addr;
				prepARPPacket(buf, tmp_ptr);
			}
			return 1;
		}
	}
    return 0;
}

void makeAndSendICMP(int len, uint8_t* packet, struct sr_instance* sr, const char* iface,
		uint8_t icmp_type, uint8_t icmp_code){

	/*packet is alway type IP*/
	printf("makeAndSendICMP function called\n");
	uint8_t * buf;
	buf = (uint8_t *)malloc(len); /*allocate new memory for buf*/
	memcpy(buf, packet, ETHE_SIZE + IP_SIZE); /*copy the ethernet and ip headers*/

	print_hdrs(buf, len);

	sr_ethernet_hdr_t *ethe_header = (sr_ethernet_hdr_t *)buf;
	struct sr_ip_hdr *ip_header = (struct sr_ip_hdr *)(buf + ETHE_SIZE);
	struct sr_icmp_hdr * icmp_header = (struct sr_icmp_hdr*)(buf + ETHE_SIZE + IP_SIZE);

	struct sr_if* out_if = sr_get_interface(sr, iface);

	if (icmp_type == 3) {
        struct sr_icmp_t3_hdr * icmp3_hdr = (struct sr_icmp_t3_hdr *)icmp_header;
		memcpy(icmp3_hdr->data, ip_header, ICMP_DATA_SIZE);
	} else {
		uint8_t * write_data_to_icmp = buf + ETHE_SIZE + IP_SIZE + ICMP_SIZE;
		memcpy(write_data_to_icmp, ip_header, ICMP_DATA_SIZE);
	}
	prepICMPPacket(icmp_header, icmp_type, icmp_code, len - ETHE_SIZE - IP_SIZE);

	populateIP(ip_header, out_if->ip, len);
	prepEthePacketFwd(buf, ((sr_ethernet_hdr_t *)packet)->ether_shost, out_if->addr);
	ethe_header->ether_type = htons(ethertype_ip);

	printf("***********ICMP packet send back**************");
	print_hdrs(buf, len);

	if (sr_send_packet(sr, buf, len, iface) < 0)
		printf("Error sending ICMP packet type %d, code %d\n", icmp_type, icmp_code);

	free(buf);
}

void prepICMPPacket(struct sr_icmp_hdr * icmp_hdr, int icmp_type, int icmp_code, int size){
    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;
    if (icmp_type == 3){
        struct sr_icmp_t3_hdr * icmp3_hdr = (struct sr_icmp_t3_hdr *)icmp_hdr;
		icmp3_hdr->unused = 0x0;
		icmp3_hdr->next_mtu = 0x0;
    }
    icmp_hdr->icmp_sum = calculate_ICMP_checksum(icmp_hdr, size);
}

int validateICMPChecksum(struct sr_icmp_hdr* icmp_hdr, int size){
    uint16_t calc_sum = calculate_ICMP_checksum(icmp_hdr, size);
    if (icmp_hdr->icmp_sum == calc_sum){
        return 1;
    }
    printf("original ICMP sum is %d, and calculated ICMP sum is %d\n",
           icmp_hdr->icmp_sum, calc_sum);
    return 0;
}

void populateIP(struct sr_ip_hdr* ip_hdr, uint32_t src_ip_addr, int len){

    ip_hdr->ip_hl = 5; /* header length */
    ip_hdr->ip_v = 4; /*version*/
    ip_hdr->ip_tos = 0; /* type of service */
    ip_hdr->ip_len = htons(len - ETHE_SIZE); /* ip data length = total length - ETHE header length*/
    ip_hdr->ip_off = 0;	/* fragment offset field */
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_id = 0;
    ip_hdr->ip_p = ip_protocol_icmp;	/* protocol */
    ip_hdr->ip_dst = ip_hdr->ip_src;
    ip_hdr->ip_src = src_ip_addr; /* source and destination address */
    ip_hdr->ip_sum = calculate_IP_checksum(ip_hdr);

}

void prepIPPacket(struct sr_ip_hdr *ip_buf){
	/*calculate the new ttl and checksum field of ip packet*/
	ip_buf->ip_ttl--;
	ip_buf->ip_sum = calculate_IP_checksum(ip_buf);
}

void prepARPPacket(uint8_t *buf, unsigned char *dest_mac_addr){
	sr_ethernet_hdr_t *ethe_header = (sr_ethernet_hdr_t *)buf;
    struct sr_arp_hdr *arp_buf = (struct sr_arp_hdr *)(buf + sizeof(struct sr_ethernet_hdr));
	int i;
	uint32_t tmp_ip;

	tmp_ip = arp_buf->ar_tip;
	arp_buf->ar_tip = arp_buf->ar_sip;
	arp_buf->ar_sip = tmp_ip;

	for (i=0; i<ETHER_ADDR_LEN; ++i){
		arp_buf->ar_tha[i] = arp_buf->ar_sha[i];
		arp_buf->ar_sha[i] = dest_mac_addr[i];
		ethe_header->ether_shost[i] = arp_buf->ar_sha[i];
		ethe_header->ether_dhost[i] = arp_buf->ar_tha[i];
	}
}

void prepEthePacketFwd(uint8_t * buf, uint8_t *dest_mac_addr, uint8_t* src_mac_addr){
	sr_ethernet_hdr_t *ethe_header = (sr_ethernet_hdr_t *)buf;

	/*change the src and dest MAC address of buf (prepare to forward)*/
	int i;
	for (i=0; i<ETHER_ADDR_LEN; ++i){
		ethe_header->ether_dhost[i] = dest_mac_addr[i];
       		ethe_header->ether_shost[i] = src_mac_addr[i];
	}
}

void prepEtheEchoReply(uint8_t * buf){
	sr_ethernet_hdr_t *ethe_header = (sr_ethernet_hdr_t *)buf;
	uint8_t tmp;
	/*change the src and dest MAC address of buf (prepare to send back)*/
	int i;
	for (i=0; i<ETHER_ADDR_LEN; ++i){
        tmp = ethe_header->ether_shost[i];
		ethe_header->ether_shost[i] = ethe_header->ether_dhost[i];
        ethe_header->ether_dhost[i] = tmp;
	}
}

void sendARPReq(int len, unsigned char* dest_mac_addr, uint32_t next_hop_ip,
    struct sr_instance* sr, const char* iface){

	/*packet is alway type IP*/
	uint8_t * buf;
	buf = (uint8_t *)malloc(len); /*allocate new memory for buf*/

	struct sr_if* out_if = sr_get_interface(sr, iface);

	sr_ethernet_hdr_t *ethe_header = (sr_ethernet_hdr_t *)buf;

	/*to send an arp request*/
	prepEthePacketFwd(buf, dest_mac_addr, out_if->addr);
	ethe_header->ether_type = htons(ethertype_arp);

	struct sr_arp_hdr *arp_header = (struct sr_arp_hdr *)(buf + sizeof(struct sr_ethernet_hdr));
	populateARP(arp_header, dest_mac_addr, next_hop_ip, out_if->addr, out_if->ip);


	if (sr_send_packet(sr, buf, len, iface) < 0)
		printf("Error sending ARP request.");

	free(buf);

}

void populateARP(struct sr_arp_hdr* arp_head, unsigned char* dest_mac_addr,
		uint32_t next_hop_ip, unsigned char* src_mac_addr, uint32_t src_ip){
	int i;
	for (i=0; i<ETHER_ADDR_LEN; ++i){
		arp_head->ar_tha[i] = dest_mac_addr[i];
		arp_head->ar_sha[i] = src_mac_addr[i];
	}
	arp_head->ar_tip = next_hop_ip;
	arp_head->ar_sip = src_ip;
	arp_head->ar_op = htons(arp_op_request);

	arp_head->ar_hrd = htons(arp_hrd_ethernet);
	arp_head->ar_pro = htons(ethertype_ip);
	arp_head->ar_hln = 6;
	arp_head->ar_pln = 4;
}

void revIPPacket(struct sr_ip_hdr* ip_buf){
    uint32_t tmp;
    tmp = ip_buf->ip_src;
    ip_buf->ip_src = ip_buf->ip_dst;
    ip_buf->ip_dst = tmp;
}

