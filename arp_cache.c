#include <stdlib.h>
#include <inttypes.h>

#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "arp_cache.h"

#define ARP_CACHE_MAX_PKT_BURST 10

bool arp_cache_force_quit;

struct arp_cache*
arp_cache_init(struct rte_mempool* mempool, int port_id, int max_pkt_burst, int entries, uint32_t sipv4) {
    struct arp_cache* arp_cache = malloc(sizeof(struct arp_cache));

    struct rte_hash_parameters parameters = { 0 };
    parameters.name = "arp_table";
    parameters.entries = entries;
    parameters.key_len = sizeof(uint32_t);
    parameters.hash_func = rte_jhash;
    parameters.hash_func_init_val = 0;
    parameters.socket_id = rte_socket_id();

    arp_cache->port_id = port_id;
    arp_cache->max_pkt_burst = max_pkt_burst;

    struct arp_cache_data* arp_data = malloc(sizeof(struct arp_cache_data));
    arp_data->table = rte_hash_create(&parameters);
    arp_data->entries = entries;
    arp_cache->data = arp_data;
    arp_cache->mempool = mempool;
    arp_cache->sipv4 = sipv4;

    return arp_cache;
}

struct rte_ether_addr*
arp_cache_lookup(struct arp_cache_data* arp_table, uint32_t ipv4) {
    struct rte_ether_addr* addr;
    int result = rte_hash_lookup_data(arp_table->table, &ipv4, (void**)&addr);
    if (result < 0) {
        printf("Failed to lookup data: %d\n", result);
        return NULL;
    }

    return addr;
}

struct rte_mbuf*
arp_cache_generate_mbuf(struct rte_mempool* mempool, uint16_t port_id, uint32_t sipv4, uint32_t tipv4) {
    struct rte_mbuf *pkt = rte_pktmbuf_alloc(mempool);
    if (pkt == NULL) {
        printf("Failed to allocate an mbuf\n");
        return NULL;
    }

    struct rte_ether_addr cfg_ether_src;
    rte_eth_macaddr_get(port_id, &cfg_ether_src); 
    struct rte_ether_addr cfg_ether_dst = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }};

    // Create Ethernet header
    struct rte_ether_hdr *eth_hdr;
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr*);
    rte_ether_addr_copy(&cfg_ether_dst, &eth_hdr->dst_addr);
    rte_ether_addr_copy(&cfg_ether_src, &eth_hdr->src_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    // Create ARP header
    struct rte_arp_hdr *arp_hdr;
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

    struct rte_ether_addr arp_tha = {0};

    struct rte_arp_ipv4 arp_data = {
        .arp_sha = cfg_ether_src,
        .arp_sip = rte_cpu_to_be_32(sipv4),
        .arp_tha = arp_tha,
        .arp_tip = rte_cpu_to_be_32(tipv4)
    };
    arp_hdr->arp_data = arp_data;

    int pkt_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

    pkt->nb_segs = 1;
    pkt->pkt_len = pkt_size;
    pkt->l2_len = sizeof(struct rte_ether_hdr);
    pkt->l3_len = sizeof(struct rte_arp_hdr);

    pkt->data_len = pkt_size;
    pkt->pkt_len = pkt_size;

    return pkt;    
}

int
arp_cache_consume_mbuf(struct arp_cache_data* arp_table, struct rte_mbuf* mbuf) {
    struct rte_ether_hdr* eth_hdr;
    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
    if (eth_hdr->ether_type != 1544) {
        printf("Not an ARP packet: %d\n", eth_hdr->ether_type);
        return 0;
    }

    struct rte_arp_hdr* arp_hdr = (struct rte_arp_hdr*)(eth_hdr + 1);
    struct rte_arp_ipv4 arp_data = arp_hdr->arp_data;

    if (arp_hdr->arp_opcode == 256) {
        printf("Given ARP mbuf is request mbuf, not response\n");
        return 0;
    } else if (arp_hdr->arp_opcode != 512) {
        printf("Unrecognized ARP Opcode\n");
        return 0;
    }

    struct in_addr sip_addr, tip_addr;
    sip_addr.s_addr = arp_data.arp_sip;
    tip_addr.s_addr = arp_data.arp_tip;

    // Sender IP: arp_data.arp_sip;
    // Sender Mac Address: arp_data.arp_sha
 
    // Copy address so it won't be deleted
    struct rte_ether_addr* addr = malloc(sizeof(struct rte_ether_addr));
    *addr = arp_data.arp_sha;

    int result = rte_hash_add_key_data(arp_table->table, &arp_data.arp_sip, &(*addr)); 

    if (result != 0) {
        printf("Failed ot add data to table\n");
        return 0;
    }

    return 1;
}

int arp_cache_lcore_reader(void *arg) {
    struct arp_cache* arp_cache = arg;
    unsigned lcore_id = rte_lcore_id();
    uint16_t queue_id = lcore_id - 1;

    struct rte_mbuf *packets[ARP_CACHE_MAX_PKT_BURST];
    uint16_t nb_rx;

    while (!arp_cache_force_quit) {
        nb_rx = rte_eth_rx_burst(arp_cache->port_id, queue_id, packets, ARP_CACHE_MAX_PKT_BURST);
        if (nb_rx == 0) {
            continue;
        }
        for (uint16_t i = 0; i < nb_rx; i++) {
            arp_cache_consume_mbuf(arp_cache->data, packets[i]);
        }
        rte_pktmbuf_free_bulk(packets, nb_rx); 
    }

    return 0;
}

int arp_cache_lcore_writer(void* arg) {
    struct arp_cache* arp_cache = arg;
    unsigned lcore_id = rte_lcore_id();
    uint16_t queue_id = lcore_id - 2;

    uint32_t ipv4s[256];
    for (int i = 0; i < 256; i++) {
        ipv4s[i] = RTE_IPV4(192, 168, 247, i);
    }

    struct rte_mbuf* packets[256];
    for (int i = 0; i < 256; i++) {
        packets[i] = arp_cache_generate_mbuf(arp_cache->mempool, arp_cache->port_id, arp_cache->sipv4, ipv4s[i]);
    }

    uint16_t nb_tx; 
    nb_tx = rte_eth_tx_burst(arp_cache->port_id, queue_id, packets, 256);
    if (nb_tx != 256) {
        printf("Failed to send packet: %d\n", nb_tx);
    }

    return 0;
}

