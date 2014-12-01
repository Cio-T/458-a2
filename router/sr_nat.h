
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

#include "sr_router.h"

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
  SYN,
  UN_SYN,
  ACK,
  FIN
  /* nat_mapping_udp, */
} connection_state;

enum nat_mapping_size {
    NAT_MAPPING_SIZE = sizeof(struct sr_nat_mapping *),
};

struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint32_t ip_conn; /* ip addr connected to*/
  uint16_t aux_conn; /* port # connected to*/

  int conn_state;
  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
	int icmp_timeout;
	int tcp_established;
	int tcp_transitory;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_instance*, int, int, int);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */
void free_nat_mapping(struct sr_nat_mapping *, struct sr_nat_mapping *,
    struct sr_nat *);
void free_walker_conns(struct sr_nat *, struct sr_nat_mapping *, time_t);
void timeout_nat_conn(struct sr_nat_connection *, struct sr_nat_connection *,
    struct sr_nat_mapping *);

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );


void updateNATConnection(struct sr_nat *, struct sr_tcp_hdr *);

#endif
