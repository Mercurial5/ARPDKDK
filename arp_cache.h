#ifndef ARP_CACHE_H
#define ARP_CACHE_H

#include <inttypes.h>
#include <pthread.h>

#include <rte_mbuf_core.h>

struct arp_cache {
    struct rte_hash *data;
    int size;
};

struct arp_cache_ipv4 {
    uint32_t ipv4;
    pthread_mutex_t mutex;
    uint8_t top;
    uint8_t current;
};

struct arp_cache_snapshot {
    struct rte_hash *data;
};

struct arp_cache_reader {
    struct arp_cache *arp_cache;
    int port_id;
    int queue_id;
    int max_pkt_burst;
    struct arp_cache_ipv4 *tipv4;
};

struct arp_cache_writer {
    struct rte_mempool *mempool;
    int port_id;
    int queue_id;
    uint32_t sipv4;
    struct arp_cache_ipv4 *tipv4;
    int tipv4_size;
    uint8_t delay;
};

/**
 * Initialize ARP Cache
 *
 * @param entries
 *   Number of entries in ARP Cache
 * @return
 *   ARP Cache structure
 */
struct arp_cache *
arp_cache_init(int entries);

/*
 * Take IPv4 Address and create arp_cache_ipv4 struct
 *
 * @param ipv4
 *   IPv4 address
 * @return
 *   arp_cache_ipv4 struct
 */
struct arp_cache_ipv4 arp_cache_create_ipv4(uint32_t ipv4);

/**
 * Lookup an ipv4 in ARP Cache and return MAC Address
 *
 * @param snapshot
 *   ARP Cache snapshot structure
 * @param ipv4
 *   IP Address of desired MAC Address
 * @param addr
 *   Return object of type uint8_t[6] where MAC Address will be saved
 */
int
arp_cache_lookup(struct arp_cache_snapshot *snapshot, uint32_t ipv4, uint16_t port_id, uint8_t* addr);

/**
 * Generate an mbuf for ARP request
 *
 * @param mempool
 *   Memory pool where mbuf will be created
 * @param port_id
 *   Port ID which will be used to get MAC Address
 * @param sipv4
 *   Sender IP Address
 * @param tipv4
 *   Target IP Address
 * @return
 *   - mbuf for ARP request
 *   - NULL if failed to allocate an mbuf
 */
struct rte_mbuf *
arp_cache_generate_mbuf(struct rte_mempool *mempool, uint16_t port_id, 
                uint32_t sipv4, uint32_t tipv4);

/**
 * Consume mbuf and add Mac Address to arp_table.
 *
 * @param arp_cache
 *   ARP Cache
 * @param mbuf
 *   Mbuf packet of ARP request
 * @param port_id
 *   PORT_ID of the device
 * @return
 *   0 - If consumed successfully
 *   -ENOMSG - If given mbuf is not ARP Response packet
 *   -ENOSPC - No space in hash
 *   -EINVAL - Error while adding to hash
 *   Possible errors:
 *   - Given mbuf is not an ARP request
 *   - Given ARP packet has opcode of a request, not response
 *   - Given ARP packet has unrecognized opcode
 *   - Failed to add MAC Address to the table
 */
int 
arp_cache_consume_mbuf(struct arp_cache *arp_cache, struct rte_mbuf *mbuf, uint16_t port_id);

/**
 * Start an lcore to read packets and call arp_cache_consume_mbuf on every packet.
 *
 * @param arg:
 *   pointer to struct arp_cache_reader
 * @return
 *   - 0 if arp_cache_force_quit is false end function is successfully ended
 */

int 
arp_cache_lcore_reader(void *arg);

/**
 * Start an lcore to send ARP packets.
 *
 * @param arg:
 *   pointer to struct arp_cache_writer
 * @return
 *   - 0 when all arp packets are sent
 */
int 
arp_cache_lcore_writer(void *arg);

/**
 * Will create a new snapshot of the current state of ARP cache
 * Every snapshot is unique, meaning this function will not 
 * return same snapshot more than once. Snapshots that will not 
 * be used should be freed with `arp_cache_free_snapshot`.
 *
 * @param arp_cache:
 *   ARP Cache structure
 * @return
 *   pointer to the ARP cache snapshot
 */
struct arp_cache_snapshot * 
arp_cache_take_snapshot(struct arp_cache *arp_cache);

/**
 * Will free snapshot that is no longer needed.
 *
 * @param to_free:
 *   pointer to the arp_cache_structure that needs to be taken care of.
 */
void 
arp_cache_free_snapshot(struct arp_cache_snapshot *to_free);

/**
 * Will stop every working threads
 */
void
arp_cache_force_quit();

#endif
