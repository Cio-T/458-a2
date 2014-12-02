
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "sr_nat.h"
#include <unistd.h>

int free_ports[64512];
int icmp_id_counter;

int sr_nat_init(struct sr_instance* sr, int icmp_timeout, int tcp_established,
	 int tcp_transitory) { /* Initializes the nat */

	struct sr_nat * nat;

	if (sr->nat == 0){
		sr->nat = (struct sr_nat *)malloc(sizeof(struct sr_nat));
	}
	nat = sr->nat;

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */
  nat->icmp_timeout = icmp_timeout;
  nat->tcp_established = tcp_established;
  nat->tcp_transitory = tcp_transitory;
  nat->extif_ip = sr_get_interface(sr, "eth2")->ip;

  init_ports();
  icmp_id_counter = 1;

  return success;
}

void init_ports(){
	int i;
	for (i=0;i<64512;i++){
		free_ports[i] = 1;
	}
}

int rand_between(int min, int max) {
    return rand() % (max - min + 1) + min;
}

int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  struct sr_nat_mapping *walker = nat->mappings;
  struct sr_nat_mapping *next_mapping = NULL;

  if (walker){
    struct sr_nat_connection *walker_conns, *next_conn;
    while ((next_mapping = walker->next)){
        next_conn = NULL;
        walker_conns = walker->conns;
        if (walker_conns){
            while ((next_conn = walker_conns->next)){
                free(walker_conns);
                walker_conns = next_conn;
            }
        }
        free(walker);
        walker = next_mapping;
    }
  }
  free(nat);

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);
    struct sr_nat_mapping *walker = nat->mappings;
    struct sr_nat_mapping *prev_mapping = NULL;
    int free_walker;
    /* handle periodic tasks here */

    while (walker){
        free_walker = 0;
        if (walker->type == nat_mapping_icmp){
            if (difftime(curtime, walker->last_updated) > nat->icmp_timeout){
                free_nat_mapping(walker, prev_mapping, nat);
                free_walker = 1;
            }
        } else if (walker->type == nat_mapping_tcp){
            free_walker_conns(nat, walker, curtime);
            if (walker->conns == NULL){
                free_nat_mapping(walker, prev_mapping, nat);
                free_walker = 1;
            }
        }
        prev_mapping = walker;
        if (free_walker){
            free(walker);
			free_ports[walker->aux_ext - 1024] = 1;
        }
        walker = prev_mapping->next;
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

void free_nat_mapping(struct sr_nat_mapping * mapping,
    struct sr_nat_mapping * prev, struct sr_nat *nat){

    if (prev){
        prev->next = mapping->next;
    } else {
        nat->mappings = mapping->next;
    }

}

void free_walker_conns(struct sr_nat *nat ,
    struct sr_nat_mapping * walker,
    time_t curtime){

    struct sr_nat_connection *walker_conns = walker->conns;
    struct sr_nat_connection *prev_conn = NULL;
    int free_conn;

    while(walker_conns){
        free_conn = 0;
        if (walker_conns->conn_state == UN_SYN){
            if (difftime(curtime, walker->last_updated) > 6.0){
                uint8_t * buf = makeIcmp(walker_conns->buf, nat->extif_ip, 3, 3);
                sendPacket(sr, buf, nat->extif_ip, LEN_ICMP);
                timeout_nat_conn(walker_conns, prev_conn, walker);
                free_conn = 1;
            }
        }else if (walker_conns->conn_state == SYN){
            if (difftime(curtime, walker->last_updated) > nat->tcp_transitory){
                timeout_nat_conn(walker_conns, prev_conn, walker);
                free_conn = 1;
            }
        }else{
            if (difftime(curtime, walker->last_updated) > nat->tcp_established){
                timeout_nat_conn(walker_conns, prev_conn, walker);
                free_conn = 1;
            }
        }
        prev_conn = walker_conns;
        if (free_conn){
            free(walker_conns);

        }
        walker_conns = prev_conn->next;
    }
}

void timeout_nat_conn(struct sr_nat_connection *conn,
    struct sr_nat_connection * prev,
    struct sr_nat_mapping *mapping){

    if (prev){
        prev->next = conn->next;
    } else {
        mapping->conns = conn->next;
    }

};

/* Get the mapping associated with given external port.
   You must not modify the returned structure externally. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *walker = nat->mappings;

  while (walker){
    if (walker->type == type && walker->aux_ext == aux_ext){
        break;
    }
    walker = walker->next;
  }
  pthread_mutex_unlock(&(nat->lock));
  return walker;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must not modify the returned structure externally. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *walker = nat->mappings;

  while (walker){
    if (walker->type == type && walker->ip_int == ip_int && walker->aux_int == aux_int){
        break;
    }
    walker = walker->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return walker;
}

/* Insert a new mapping into the nat's mapping table.
   Return the new mapping, must not modify the returned structure.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat, uint32_t ip_int,
	uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;
  struct sr_nat_mapping *walker = nat->mappings;

  mapping = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
  mapping->type = type;
  mapping->conns = NULL;
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->ip_ext = nat->extif_ip;

  if (mapping->type == nat_mapping_tcp){
    int i = rand_between(1, 64511);
    while (!free_ports[i])
        i = rand_between(1, 64511);
    mapping->aux_ext = i + 1024;
    free_ports[i] = 0;
  } else {
    mapping->aux_ext = icmp_id_counter;
    if (icmp_id_counter < 65535)
        ++icmp_id_counter;
    else
        icmp_id_counter = 1;
  }

  if (walker){
  	mapping->next = walker->next;
  	walker->next = mapping;
  } else {
  	mapping->next = NULL;
  	nat->mappings = mapping;
  }
  mapping->last_updated = time(NULL);
  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}


int updateNATConnection(struct sr_nat_connection * find_conn, uint8_t tcp_flag, int isClient){

		int cur_conn = find_conn->conn_state;
		if (cur_conn == UN_SYN){
			if (isClient && tcp_flag == FLAG_SYN)
				find_conn->conn_state = CONN;
		} else if (cur_conn == SYN){
			if (!isClient){
				if (tcp_flag == FLAG_SYN_ACK)
					find_conn->conn_state = SYN_ACK;
				else if (tcp_flag == FLAG_SYN)
                    find_conn->conn_state = CONN;

			}
		} else if (cur_conn == SYN_ACK){
			if (isClient && tcp_flag == FLAG_ACK)
				find_conn->conn_state = CONN;
		} else if (cur_conn == CONN){
			if (tcp_flag == FLAG_FIN){
				if (isClient)
					find_conn->conn_state = FIN_C;
				else
					find_conn->conn_state = FIN_S;
			}
		} else if (cur_conn == FIN_C) {
			if (!isClient){
				if (tcp_flag == FLAG_FIN_ACK)
					find_conn->conn_state = FIN_ACK_S;
				else if (tcp_flag == FLAG_FIN)
					find_conn->conn_state = FIN_S2;
			}
		} else if (cur_conn == FIN_S) {
			if (isClient){
				if (tcp_flag == FLAG_FIN_ACK)
					find_conn->conn_state = FIN_ACK_C;
				else if (tcp_flag == FLAG_FIN)
					find_conn->conn_state = FIN_C2;
			}
		} else if (cur_conn == FIN_ACK_S) {
			if (!isClient && tcp_flag == FLAG_FIN)
				find_conn->conn_state = FIN_S2;
		} else if (cur_conn == FIN_ACK_C) {
			if (isClient && tcp_flag == FLAG_FIN)
				find_conn->conn_state = FIN_C2;
		} else if (cur_conn == FIN_S2) {
			if (isClient && tcp_flag == FLAG_ACK)
				return 1;
		} else if (cur_conn == FIN_C2) {
			if (!isClient && tcp_flag == FLAG_ACK)
				return 1;
		}
		return 0;
}

void insertNATConnection(struct sr_nat_mapping * mapping, uint8_t* buf, uint32_t ip_conn,
	uint16_t aux_conn, int conn_state){

	struct sr_nat_connection *new_conn = NULL;
	struct sr_nat_connection *conns = mapping->conns;

	new_conn = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));
	new_conn->ip_conn = ip_conn;
	new_conn->aux_conn = aux_conn;

	if (conns){
		new_conn->next = conns->next;
		conns->next = new_conn;
	} else {
		new_conn->next = NULL;
		mapping->conns = new_conn;
	}
	new_conn->conn_state = conn_state;
	new_conn->buf = NULL;
	if (conn_state == UN_SYN){
        struct sr_ip_hdr *ip_hdr_buf = (struct sr_ip_hdr *)(buf + ETHE_SIZE);
        new_conn->buf = malloc(ICMP_DATA_SIZE);
        memcpy(new_conn->buf, ip_hdr_buf, ICMP_DATA_SIZE);
	}

}

int processNATConnection(struct sr_nat *nat, uint8_t* buf, struct sr_nat_mapping * mapping,
	uint32_t ip_conn, uint16_t aux_conn, uint8_t tcp_flag, int isClient){

	pthread_mutex_lock(&(nat->lock));

	struct sr_nat_connection *walker_conns = mapping->conns;
	struct sr_nat_connection *prev_conn = NULL;
	int found = 0;

    while(walker_conns){
		if (walker_conns->ip_conn == ip_conn && walker_conns->aux_conn == aux_conn){
			found = 1;
			break;
		}
        prev_conn = walker_conns;
        walker_conns = prev_conn->next;
    }

	if (!found){
		if (tcp_flag == FLAG_SYN){
			if (isClient){
				insertNATConnection(mapping, ip_conn, aux_conn, SYN);
			} else {
				insertNATConnection(mapping, ip_conn, aux_conn, UN_SYN);
				pthread_mutex_unlock(&(nat->lock));
				return 1;
			}
		}
	} else {
		if (updateNATConnection(walker_conns, tcp_flag, isClient))
			timeout_nat_conn(walker_conns, prev_conn, mapping);
	}

	mapping->last_updated = time(NULL);
	pthread_mutex_unlock(&(nat->lock));
	return 0;
}
