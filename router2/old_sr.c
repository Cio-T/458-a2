/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

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

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

	uint8_t *buf;
	buf = (uint8_t *)malloc(len); /*allocate new memory for buf*/
	memcpy(buf, packet, len); /*let buf be a deep copy of the ethernet packet received*/

    if (ethertype(buf) == ethertype_ip){/*If the ethernet packet received has protocol IP*/

        struct sr_ip_hdr *ip_buf = (struct sr_ip_hdr *)(buf + sizeof(struct sr_ethernet_hdr));
 		printf("Time to live is %d\n", ip_buf->ip_ttl);
	    if (validIPPacket(ip_buf)){
			if (ip_buf->ip_ttl < 2) {
        		printf("ERROR: Time to live has expired\n");
 		       /*send ICMP Time exceeded (type 11, code 0)*/
				len = ETHE_SIZE + IP_SIZE + ICMP_SIZE + ICMP_DATA_SIZE;
				makeAndSendICMP(len, buf, sr, interface, 11, 0);
			} else {
				prepIPPacket(ip_buf);
				if (packetIsToSelf(sr, buf, 1, interface)){
					printf("IP packet is to self\n");
					if (ip_buf->ip_p == ip_protocol_icmp) {
						printf("IP protocol is ICMP\n");
						struct sr_icmp_hdr * icmp_hdr = (struct sr_icmp_hdr *)(buf + ETHE_SIZE + IP_SIZE);
						int icmp_size = len - (ETHE_SIZE + IP_SIZE);
						if (validateICMPChecksum(icmp_hdr, icmp_size)){
        	                /*check if packet is ICMP echo request (type 8) */
            	            if (icmp_hdr->icmp_type == 8){
                	            printf("ICMP protocol is echo request\n");
                    	        /*if yes, send back ICMP reply (type 0)*/
								/*COMPLETED - not tested?*/
								len = ETHE_SIZE + IP_SIZE + ICMP_SIZE + ICMP_DATA_SIZE;
								icmp_size = len - (ETHE_SIZE + IP_SIZE);
								uint8_t * write_data_to_icmp = buf + ETHE_SIZE + IP_SIZE + ICMP_SIZE;
								memcpy(write_data_to_icmp, ip_buf, ICMP_DATA_SIZE);
            	                prepICMPPacket(icmp_hdr, 0, 0, icmp_size);
                	            revIPPacket(ip_buf);
                    	        prepEtheEchoReply(buf);
	
    	                        if (sr_send_packet(sr, buf, len, interface) < 0)
                 	               printf("Error sending ICMP Echo reply.");
                    	    }
						}
	
					} else {
						/*IP packet containing a UDP or TCP payload. 
						Send ICMP Port unreachable (type 3, code 3)*/ 	
						printf("packet is to self and packet has TCP payload\n");
						len = ETHE_SIZE + IP_SIZE + ICMP3_SIZE + ICMP_DATA_SIZE;
						makeAndSendICMP(len, buf, sr, interface, 3, 3);
					}

				} else {
    		        /*Determine if packet should be forwarded*/
        		    struct sr_rt* best_rt_entry = getBestRtEntry(sr->routing_table, ip_buf);

            		if (!best_rt_entry){/*no matching entry in routing table*/
                		/*send ICMP Destination net unreachable (type 3, code 0)*/
						len = ETHE_SIZE + IP_SIZE + ICMP3_SIZE + ICMP_DATA_SIZE;
						makeAndSendICMP(len, buf, sr, interface, 3, 0);
	    	        }else{
						interface = best_rt_entry->interface;
        	    	    /*find next hop ip address based on longest prefix match entry in rtable*/
            	    	uint32_t next_hop_ip = best_rt_entry->gw.s_addr;
  	  		            /*deal with ARP*/
    	    	        struct sr_arpentry *next_hop_ip_lookup;
            		    if ((next_hop_ip_lookup = sr_arpcache_lookup(&(sr->cache), next_hop_ip))){
        	    	        /*Forward packet*/
        	        	    /*COMPLETED*/
							uint8_t *dest_mac_addr = next_hop_ip_lookup->mac;
							struct sr_if* out_if = sr_get_interface(sr, interface);
							prepEthePacketFwd(buf, dest_mac_addr, out_if->addr);
							if (sr_send_packet(sr, buf, len, interface) < 0)
								printf("Error forwarding IP packet.");
    		            	
							free(next_hop_ip_lookup);
    	    		    } else {
        	    			struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, buf,
																			len, interface);
        	    	    	sr_handle_arpreq(sr, req);
   		    	        }
	
    		        }
		        }
			}
		}

	} else if (ethertype(buf) == ethertype_arp){/*If the ethernet packet received is type ARP*/
        struct sr_arp_hdr *arp_buf = (struct sr_arp_hdr *)(buf + sizeof(struct sr_ethernet_hdr));
		if (packetIsToSelf(sr, buf, 0, interface)){
    	   	if (ntohs(arp_buf->ar_op) == arp_op_reply){/*If the ARP packet is ARP reply*/
        	   	/*COMPLETED*/
 	          	sr_process_arpreply(sr, arp_buf->ar_sha, arp_buf->ar_sip);
   			} else if (ntohs(arp_buf->ar_op) == arp_op_request){/*If the ARP packet is ARP request*/
				/*COMPLETED*/
   	    	    /*Send ARP reply packet to the sender*/
				arp_buf->ar_op = htons(arp_op_reply);
				len = ETHE_SIZE + ARP_SIZE; 
				if (sr_send_packet(sr, buf, len, interface) < 0)
					printf("Error sending ARP reply.");
	     	} else {
   		        printf("Error: undefined ARPtype. Dropping packet.");
				/*drop packet*/
	        }
		}
	} else {
	    printf("Error: undefined ethernet type. Dropping packet.");
	}

	free(buf);
}/* end sr_ForwardPacket */

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

