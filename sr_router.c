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

	struct sr_if* in_if = sr_get_interface(sr, interface);

	if (ethertype(buf) == ethertype_ip){/*If the ethernet packet received has protocol IP*/
	} else if (ethertype(buf) == ethertype_arp){/*If the ethernet packet received is type ARP*/
		struct sr_arp_hdr *arp_buf = (struct sr_arp_hdr *)(buf + sizeof(struct sr_ethernet_hdr));
   	    	    /*Send ARP reply packet to the sender*/
				arp_buf->ar_op = htons(arp_op_reply);
				prepArpReply(buf);
				prepEtheFwd(buf, arp_buf->ar_tha, in_if->addr);
				if (sr_send_packet(sr, buf, len, interface) < 0)
					printf("Error sending ARP reply.");
	} else {
	    printf("Error: undefined ethernet type. Dropping packet.");
	}
}/* end sr_ForwardPacket */

