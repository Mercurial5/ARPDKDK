#ifndef ARP_CACHE_H
#define ARP_CACHE_H

#include <inttypes.h>

#include <rte_mbuf_core.h>

struct arp_cache_table {
    struct rte_hash* table;
};

/**
 * Initialize ARP Table
 *
 * @param entries
 *   Number of entries in ARP Table
 * @return
 *   ARP Table structure
 */
struct arp_cache_table* arp_cache_table_init(int entries);

/**
 * Lookup an ipv4 in ARP Table and return MAC Address
 *
 * @param arp_table
 *   ARP Table structure
 * @param ipv4
 *   IP Address of desired MAC Address
 * @return
 *   - MAC Address
 *   - NULL if given ip does not exists in ARP Table
 */
struct rte_ether_addr* arp_cache_lookup(struct arp_cache_table* arp_table, uint32_t ipv4);

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
struct rte_mbuf* arp_cache_generate_mbuf(struct rte_mempool* mempool, uint16_t port_id, uint32_t sipv4, uint32_t tipv4);

/**
 * Consume mbuf and add Mac Address to arp_table.
 *
 * @param arp_table
 *   ARP Table structure
 * @param mbuf
 *   Mbuf packet of ARP request
 * @return
 *   On success - 1
 *   On error - 0
 *   Possible errors:
 *   - Given mbuf is not an ARP request
 *   - Given ARP packet has opcode of a request, not response
 *   - Given ARP packet has unrecognized opcode
 *   - Failed to add MAC Address to the table
 */
int arp_cache_consume_mbuf(struct arp_cache_table* arp_table, struct rte_mbuf* mbuf);

#endif
