#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>

#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "arp_cache.h"

bool arp_cache_force_quit_;
struct rte_ether_addr ETHER_BROADCAST = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }};

struct arp_cache_hash_key {
    uint32_t ipv4;
    uint16_t port_id;
};

uint64_t
arp_cache_serialize_addr(uint8_t addr[6]) {
    uint64_t serialized = 0;

    for (int i = 0; i < 6; i++) {
        serialized += (uint64_t)addr[i] << (i * 8);
    }

    return serialized;
}

void
arp_cache_deserialize_addr(uint64_t addr, uint8_t* deserialized) {
    for (int i = 5; i >= 0; i--) {
        deserialized[i] = addr >> (i * 8);
    }
}

struct rte_hash *
arp_cache_create_rte_hash(int entries) {
    static int count = 0;
    struct rte_hash *hash;
    struct rte_hash_parameters parameters = { 0 };
    char name[100];

    sprintf(name, "arp_cache_table_%d", count++);

    parameters.name = name;
    parameters.entries = entries;
    parameters.key_len = sizeof(struct arp_cache_hash_key);
    parameters.hash_func = rte_jhash;
    parameters.hash_func_init_val = 0;
    parameters.socket_id = rte_socket_id();

    hash = rte_hash_create(&parameters);
    return hash;
}

void
arp_cache_copy_rte_hash(struct rte_hash *ihash, struct rte_hash *ohash) {
    uint32_t iterator = 0;
    int result;
    uint32_t *key;
    uint64_t data;

    while (true) {
        result = rte_hash_iterate(ihash, (void*)&key, (void**)&data, &iterator);
        if (-result == ENOENT) {
            break;
        }

        result = rte_hash_add_key_data(ohash, key, (void*)data);
        if (result != 0) {
            printf("Failed to copy data to rte_hash\n");
        }
    }
}

struct arp_cache*
arp_cache_init(int entries) {
    struct arp_cache* arp_cache;

    arp_cache = malloc(sizeof(struct arp_cache));
    arp_cache->data = arp_cache_create_rte_hash(entries);
    arp_cache->size = entries;

    return arp_cache;
}

int
arp_cache_lookup(struct arp_cache_snapshot* snapshot, uint32_t ipv4, uint16_t port_id, uint8_t* addr) {
    struct arp_cache_hash_key hash_key;
    int result;
    uint64_t data;

    hash_key.ipv4 = ipv4;
    hash_key.port_id = port_id;

    result = rte_hash_lookup_data(snapshot->data, &hash_key, (void**)&data);
    if (result < 0) {
        return result;
    }

    arp_cache_deserialize_addr(data, addr);
    return 0;
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
    arp_hdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp_hdr->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp_hdr->arp_plen = 4;
    arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);
    
    // Create arp data
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
    uint64_t serialized;

    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);

    // Not an ARP packet
    if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
        return -ENOMSG;
    }

    arp_hdr = (struct rte_arp_hdr*)(eth_hdr + 1);
    arp_data = arp_hdr->arp_data;
    
    // Given ARP mbuf is request mbuf, not response
    if (arp_hdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
        return -ENOMSG;
    }
    // Unrecognized ARP Opcode
    else if (arp_hdr->arp_opcode != rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
        return -ENOMSG;
    }

    serialized = arp_cache_serialize_addr(arp_data.arp_sha.addr_bytes);

    hash_key.ipv4 = arp_data.arp_sip;
    hash_key.port_id = port_id;
    result = rte_hash_add_key_data(arp_cache->data, &hash_key, (void*)serialized); 

    if (result != 0) {
        return result;
    }

    return 0;
}

int arp_cache_lcore_reader(void *arg) {
    struct arp_cache_reader* arp_cache_reader = arg;
    struct rte_mbuf *packets[arp_cache_reader->max_pkt_burst];
    uint16_t nb_rx;

    while (!arp_cache_force_quit_) {
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

struct arp_cache_snapshot * 
arp_cache_take_snapshot(struct arp_cache *arp_cache) {
    struct arp_cache_snapshot *snapshot;

    snapshot = malloc(sizeof(struct arp_cache_snapshot));
    snapshot->data = arp_cache_create_rte_hash(arp_cache->size);
    arp_cache_copy_rte_hash(arp_cache->data, snapshot->data);

    return snapshot;
}

void 
arp_cache_free_snapshot(struct arp_cache_snapshot *to_free) {
    rte_hash_free(to_free->data);
    free(to_free);
}

void
arp_cache_force_quit() {
    arp_cache_force_quit_ = true;
}


