# ARPDPDK

This is a library that implements ARP request using DPDK.

## Getting started

> Note: working example is written in main.c

### Initializing APR Table

First of all, you need to create an `arp_cache` object, passing number of entries
to the ARP table;
```
int arp_entries = 100;
struct arp_cache *arp_cache = arp_cache_init(arp_entries);
```

### Generating mbuf

In order to generate an ARP mbuf, call `arp_cache_generate_mbuf` function:

```
struct rte_mempool *mempool;
uint16_t port_id;
uint32_t sipv4;
uint32_t tipv4;

struct rte_mbuf *mbuf;
mbuf = arp_cache_generate_mbuf(mempool, port_id, sipv4, tipv4);
```

You can then send this mbuf to tx queue.

### Consuming mbuf

When you receive an ARP response, you can save it's entries to ARP Cache using `arp_cache_consume_mbuf` function:

```
int result;
struct arp_cache* arp_cache;
struct rte_mbuf* mbuf

result = arp_cache_consume_mbuf(arp_cache, mbuf);
if (result == 1) {
    printf("Successfully consumed an mbuf\n");
}
```

### Lookup

After consuming ARP mbuf, you can lookup MAC Address of desired IP:

```
struct arp_cache* arp_cache;
uint32_t ipv4;

rte_ether_addr* addr;
addr = arp_cache_lookup(arp_cache, ipv4);
if (addr == NULL) {
    printf("Given address does not yet exists in ARP cache\n");
}
```

### lcore reader

ARP Cache library provides `arp_cache_lcore_reader`, that consumes packets and 
calls `arp_cache_consume_mbuf` on every packet. Example usage:

```
struct arp_cache *arp_cache;
int PORT_ID;
int QUEUE_ID;
int MAX_PKT_BURST;

struct arp_cache_reader arp_cache_reader = {
        .arp_cache = arp_cache,
        .port_id = PORT_ID,
        .queue_id = QUEUE_ID,
        .max_pkt_burst = MAX_PKT_BURST
    };

int lcore_id = 1;
rte_eal_remote_launch(arp_cache_lcore_reader, &arp_cache_reader, lcore_id); 
```


### lcore writer

ARP Cache library provides `arp_cache_lcore_writer`, that will write ARP mbufs 
to tx queue. Example usage:

```
// Sender IPv4
uint32_t sipv4 = RTE_IPV4(192, 168, 100, 100);

// Target IPv4 array size
int tipv4_size = 256;

// Target IPv4s
uint32_t tipv4[tipv4_size];
for (int i = 0; i < tipv4_size; i++) {
    tipv4[i] = RTE_IPV4(192, 168, 100, i);
}

struct rte_mempool *mempool;
int PORT_ID;
int QUEUE_ID;
struct arp_cache_writer arp_cache_writer = {
    .mempool = mempool,
    .port_id = PORT_ID,
    .queue_id = QUEUE_ID,
    .sipv4 = sipv4,
    .tipv4 = tipv4,
    .tipv4_size = tipv4_size
};

int lcore_id = 1;
rte_eal_remote_launch(arp_cache_lcore_writer, &arp_cache_writer, lcore_id);
```

### arp_cache_force_quit

In order to stop `arp_cache_lcore_reader` and `arp_cache_lcore_writer`, set `arp_cache_force_quit` variable to `false`
