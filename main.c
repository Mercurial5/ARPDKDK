#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <signal.h>

#include <arpa/inet.h>

#include <rte_ethdev.h>

#include "arp_cache.h"

#define PORT_ID 0
#define IP_1 192
#define IP_2 168
#define IP_3 0
#define IP_4 21

bool force_quit;

void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, exiting\n", signum); 
        arp_cache_force_quit();
        force_quit = true;
    }
}

int lcore_reader(void *arg) {
    struct arp_cache *arp_cache = arg;
    struct arp_cache_snapshot* arp_cache_snapshot = arp_cache_take_snapshot(arp_cache);
    unsigned lcore_id = rte_lcore_id();
     
    uint32_t ips_to_lookup[256];
    
    for (int i = 0; i < 256; i++) {
        ips_to_lookup[i] = rte_cpu_to_be_32(RTE_IPV4(IP_1, IP_2, IP_3, i));
    }

    for (int i = 0; i < 256; i++) {
        uint8_t addr[6];
        int ret = arp_cache_lookup(arp_cache_snapshot, ips_to_lookup[i], PORT_ID, addr);
        if (ret < 0) {
            continue;
        } else {
            struct in_addr ip_addr;
            ip_addr.s_addr = ips_to_lookup[i];

            printf("IP Address (%d): %s\n", lcore_id, inet_ntoa(ip_addr)); 
            printf("MAC Address (%d): ", lcore_id); 
            for (int i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
                printf("%x", (int) addr[i]); 
                if (i != RTE_ETHER_ADDR_LEN - 1) {
                    printf(":");
                }
            }
            printf("\n");
        }
    }

    arp_cache_free_snapshot(arp_cache_snapshot);

    return 0;
}

int main(int argc, char **argv) {
    int error;
    if ((error = rte_eal_init(argc, argv)) == -1) {
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments: %s\n", rte_strerror(-error));
    }
    
    // create mbuf pool
    const char name[] = "mbpool";
    struct rte_mempool *mempool = rte_pktmbuf_pool_create(name, 4095, 250, 0, 4095, SOCKET_ID_ANY);
    
    // configure ethernet device
    struct rte_eth_conf dev_conf = {};
    if ((error = rte_eth_dev_configure(PORT_ID, 1, 1, &dev_conf)) < 0) {
        rte_exit(EXIT_FAILURE, "Could not configure eth device: %s\n", rte_strerror(-error));
    }
    
    // configure tx queue
    struct rte_eth_rxconf rx_conf = {};
    if ((error = rte_eth_rx_queue_setup(PORT_ID, 0, 0, SOCKET_ID_ANY, &rx_conf, mempool)) < 0) {
        rte_exit(EXIT_FAILURE, "Could not configure rx queue: %s\n", rte_strerror(-error));
    }

    struct rte_eth_txconf tx_conf = {};
    if ((error = rte_eth_tx_queue_setup(PORT_ID, 0, 0, SOCKET_ID_ANY, &tx_conf)) < 0) {
        rte_exit(EXIT_FAILURE, "Could not configure tx queue: %s\n", rte_strerror(-error));
    }

    // start ethernet device
    if ((error = rte_eth_dev_start(PORT_ID)) < 0) {
        rte_exit(EXIT_FAILURE, "Could not start eth device: %s\n", rte_strerror(-error));
    }

    if ((error = rte_eth_promiscuous_enable(PORT_ID)) < 0) {	
        rte_exit(EXIT_FAILURE, "Could not enable promiscuous mode: %s\n", rte_strerror(-error));
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    struct arp_cache *arp_cache = arp_cache_init(100);

    struct arp_cache_reader arp_cache_reader = {
        .arp_cache = arp_cache,
        .port_id = PORT_ID,
        .queue_id = 0,
        .max_pkt_burst = 10
    };
    
    rte_eal_remote_launch(arp_cache_lcore_reader, &arp_cache_reader, 1); 

    uint32_t sipv4 = RTE_IPV4(IP_1, IP_2, IP_3, IP_4);
    int tipv4_size = 256;
    struct arp_cache_ipv4 tipv4[tipv4_size];
    for (int i = 0; i < tipv4_size; i++) {
        tipv4[i] = arp_cache_create_ipv4(RTE_IPV4(IP_1, IP_2, IP_3, i));
    }
    
    printf("test\n");
    struct arp_cache_writer arp_cache_writer = {
        .mempool = mempool,
        .port_id = PORT_ID,
        .queue_id = 0,
        .sipv4 = sipv4,
        .tipv4 = tipv4,
        .tipv4_size = tipv4_size,
        .delay = 1
    };

    rte_eal_remote_launch(arp_cache_lcore_writer, &arp_cache_writer, 2);
    
    for (int i = 0; i < 100 && !force_quit; i++) {
        rte_eal_remote_launch(lcore_reader, arp_cache, 3); 
        rte_eal_wait_lcore(3);
        sleep(5);
    }

    rte_eal_wait_lcore(1);
    rte_eal_wait_lcore(2);

    return 0;
}

