#include <stdlib.h>
#include <inttypes.h>

#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "arp_cache.h"

#define ARP_CACHE_MAX_PKT_BURST 10

bool arp_cache_force_quit;
struct rte_ether_addr ETHER_BROADCAST = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }};

struct arp_cache_hash_key {
    uint32_t ipv4;
    uint16_t port_id;
};

struct arp_cache*
arp_cache_init(int entries) {
    struct arp_cache* arp_cache;
    struct rte_hash_parameters parameters;

    arp_cache = malloc(sizeof(struct arp_cache));

    parameters.name = "arp_cache_table";
    parameters.entries = entries;
    parameters.key_len = sizeof(struct arp_cache_hash_key);
    parameters.hash_func = rte_jhash;
    parameters.hash_func_init_val = 0;
    parameters.socket_id = rte_socket_id();

    arp_cache->data = rte_hash_create(&parameters);

    return arp_cache;
}

struct rte_ether_addr*
arp_cache_lookup(struct arp_cache* arp_cache, uint32_t ipv4, uint16_t port_id) {
    struct arp_cache_hash_key hash_key;
    struct rte_ether_addr* addr;

    hash_key.ipv4 = ipv4;
    hash_key.port_id = port_id;

    int result = rte_hash_lookup_data(arp_cache->data, &hash_key, (void**)&addr);
    if (result < 0) {
        // printf("Failed to lookup data: %d\n", result);
        return NULL;
    }

    return addr;
}

struct rte_mbuf*
arp_cache_generate_mbuf(struct rte_mempool* mempool, uint16_t port_id, uint32_t sipv4, uint32_t tipv4) {
    struct rte_mbuf *pkt;
    struct rte_ether_addr cfg_ether_src;
    struct rte_ether_hdr *eth_hdr;
    struct rte_arp_hdr *arp_hdr;
    struct rte_ether_addr arp_tha = { 0 };
    struct rte_arp_ipv4 arp_data;
    int pkt_size;

    pkt = rte_pktmbuf_alloc(mempool);
    if (pkt == NULL) {
        printf("Failed to allocate an mbuf\n");
        return NULL;
    }
    
    rte_eth_macaddr_get(port_id, &cfg_ether_src);     

    // Create Ethernet header
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr*);
    rte_ether_addr_copy(&ETHER_BROADCAST, &eth_hdr->dst_addr);
    rte_ether_addr_copy(&cfg_ether_src, &eth_hdr->src_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    // Create ARP header
    arp_hdr = (struct rte_arp_hdr *) (eth_hdr + 1);

    // arp_hdr->arp_hardware = RTE_ARP_HRD_ETHER;
    arp_hdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);

    // arp_hdr->arp_protocol = RTE_ETHER_TYPE_IPV4;
    arp_hdr->arp_protocol = 8;
    arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;

    /* 
     * This field should equal to 4 bytes. RTE_ETHER_CRC_LEN is also 4 bytes,
     * but is the meaning correct? 
     */
    arp_hdr->arp_plen = RTE_ETHER_CRC_LEN;

    // arp_hdr->arp_opcode = RTE_ARP_OP_REQUEST;
    arp_hdr->arp_opcode = 256;


    arp_data.arp_sha = cfg_ether_src;
    arp_data.arp_sip = rte_cpu_to_be_32(sipv4);
    arp_data.arp_tha = arp_tha;
    arp_data.arp_tip = rte_cpu_to_be_32(tipv4);

    arp_hdr->arp_data = arp_data;

    pkt_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

    pkt->nb_segs = 1;
    pkt->pkt_len = pkt_size;
    pkt->l2_len = sizeof(struct rte_ether_hdr);
    pkt->l3_len = sizeof(struct rte_arp_hdr);

    pkt->data_len = pkt_size;
    pkt->pkt_len = pkt_size;

    return pkt;    
}

int
arp_cache_consume_mbuf(struct arp_cache* arp_cache, struct rte_mbuf* mbuf, uint16_t port_id) {
    struct rte_ether_hdr* eth_hdr;
    struct rte_arp_hdr* arp_hdr;
    struct rte_arp_ipv4 arp_data;
    struct rte_ether_addr* addr;
    struct arp_cache_hash_key hash_key;
    int result;

    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
    if (eth_hdr->ether_type != 1544) {
        // printf("Not an ARP packet: %d\n", eth_hdr->ether_type);
        return 0;
    }

    arp_hdr = (struct rte_arp_hdr*)(eth_hdr + 1);
    arp_data = arp_hdr->arp_data;

    if (arp_hdr->arp_opcode == 256) {
        printf("Given ARP mbuf is request mbuf, not response\n");
        return 0;
    } else if (arp_hdr->arp_opcode != 512) {
        printf("Unrecognized ARP Opcode\n");
        return 0;
    }
  
    // Copy address so it won't be deleted
    addr = malloc(sizeof(struct rte_ether_addr));
    *addr = arp_data.arp_sha;
    
    hash_key.ipv4 = arp_data.arp_sip;
    hash_key.port_id = port_id;
    result = rte_hash_add_key_data(arp_cache->data, &hash_key, &(*addr)); 

    if (result != 0) {
        printf("Failed ot add data to table\n");
        return 0;
    }

    return 1;
}

int arp_cache_lcore_reader(void *arg) {
    struct arp_cache_reader* arp_cache_reader = arg;
    struct rte_mbuf *packets[arp_cache_reader->max_pkt_burst];
    uint16_t nb_rx;

    while (!arp_cache_force_quit) {
        nb_rx = rte_eth_rx_burst(arp_cache_reader->port_id, arp_cache_reader->queue_id, packets, arp_cache_reader->max_pkt_burst);
        if (nb_rx == 0) {
            continue;
        }
        for (uint16_t i = 0; i < nb_rx; i++) {
            arp_cache_consume_mbuf(arp_cache_reader->arp_cache, packets[i], arp_cache_reader->port_id);
        }
        rte_pktmbuf_free_bulk(packets, nb_rx); 
    }

    return 0;
}

int arp_cache_lcore_writer(void* arg) {
    struct arp_cache_writer* arp_cache_writer = arg;
    struct rte_mbuf* packets[arp_cache_writer->tipv4_size];
    uint16_t nb_tx;

    for (int i = 0; i < arp_cache_writer->tipv4_size; i++) {
        packets[i] = arp_cache_generate_mbuf(arp_cache_writer->mempool, arp_cache_writer->port_id, arp_cache_writer->sipv4, arp_cache_writer->tipv4[i]);
    }

    nb_tx = rte_eth_tx_burst(arp_cache_writer->port_id, arp_cache_writer->queue_id, packets, arp_cache_writer->tipv4_size);
    if (nb_tx != arp_cache_writer->tipv4_size) {
        printf("Failed to send packet: %d\n", nb_tx);
    }

    return 0;
}

