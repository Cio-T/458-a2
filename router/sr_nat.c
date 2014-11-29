
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "sr_nat.h"
#include <unistd.h>

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

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

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
    struct sr_nat_mapping *prev = NULL;
    /* handle periodic tasks here */

    while (walker){
        if (walker->type == nat_mapping_icmp){
            if (difftime(curtime, walker->last_updated) > nat->icmp_timeout){
                free_nat_mapping(walker, prev, mat);
            }
        } else if (walker->type == nat_mapping_tcp){

        }
        prev = walker;
        walker = walker->next;
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

void free_nat_mapping(struct sr_nat_mapping * walker,
    struct sr_nat_mapping * prev, struct sr_nat *nat){

        if (prev){
            prev->next = walker->next;
        } else {
            nat->mappings = walker->next;
        }

}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *walker = nat->mappings;

  while (walker){
    if (walker->type == type && walker->aux_ext == aux_ext){
        copy = malloc(NAT_MAPPING_SIZE);
        memcpy(copy, walker, NAT_MAPPING_SIZE);
	break;
    }
    walker = walker->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *walker = nat->mappings;

  while (walker){
    if (walker->type == type && walker->ip_int == ip_int && walker->aux_int == aux_int){
        copy = malloc(NAT_MAPPING_SIZE);
        memcpy(copy, walker, NAT_MAPPING_SIZE);
	break;
    }
    walker = walker->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *walker = nat->mappings;

  while (walker){
    walker = walker->next;
  }

  mapping = (struct sr_nat *)malloc(sizeof(struct sr_nat));
  mapping->type = type;
  mapping->conns = NULL;
  if (mapping->type == nat_mapping_tcp){

  }
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->ip_ext = 0;
  mapping->aux_ext = 0;

  mapping->next = NULL;
  walker->next = mapping;
  memcpy(copy, mapping, NAT_MAPPING_SIZE);

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}
