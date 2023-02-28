#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#define IP_TCP 6

/* A synproxy connection */
struct synproxy_conn {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
};

/* The hash table to store the synproxy connections */
struct bpf_map_def SEC("maps") synproxy_conns = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct synproxy_conn),
    .value_size = sizeof(int),
    .max_entries = 9999999,
    .map_flags = BPF_F_NO_PREALLOC,
};

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (eth + 1 > (struct ethhdr *)data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 > (struct iphdr *)data_end)
        return XDP_PASS;

    if (ip->protocol != IP_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = data + sizeof(struct ethhdr) + ip->ihl * 4;
    if (tcp + 1 > (struct tcphdr *)data_end)
        return XDP_PASS;

    /* If it is a TCP SYN packet */
    if (tcp->syn && !tcp->ack) {
        struct synproxy_conn conn = {
            .saddr = ip->saddr,
            .daddr = ip->daddr,
            .sport = tcp->source,
            .dport = tcp->dest,
        };

        int *entry = bpf_map_lookup_elem(&synproxy_conns, &conn);
        if (entry) {
            /* We already have this connection in our table, drop the packet */
            return XDP_DROP;
        } else {
            /* This is a new connection, add it to our table and proxy the SYN packet */
            int value = 1;
            bpf_map_update_elem(&synproxy_conns, &conn, &value, BPF_ANY);
            return XDP_PASS;
        }
    }

    /* If it is a TCP SYN-ACK packet */
    if (tcp->syn && tcp->ack) {
        struct synproxy_conn conn = {
            .daddr = ip->saddr,
            .saddr = ip->daddr,
            .dport = tcp->source,
            .sport = tcp->dest,
        };

        int *entry = bpf_map_lookup_elem(&synproxy_conns, &conn);
        if (entry) {
  /* We have seen the SYN packet before, this is the SYN-ACK reply */
        bpf_map_delete_elem(&synproxy_conns, &conn);
        return XDP_DROP;
    } else {
        /* This is a SYN-ACK packet for a connection we haven't seen before, drop it */
        return XDP_DROP;
    }
}

/* If it is a TCP packet for an existing connection */
struct synproxy_conn conn = {
    .saddr = ip->saddr,
    .daddr = ip->daddr,
    .sport = tcp->source,
    .dport = tcp->dest,
};

int *entry = bpf_map_lookup_elem(&synproxy_conns, &conn);
if (entry) {
    /* We have seen this connection before, forward the packet */
    return XDP_PASS;
} else {
    /* This is not a known connection, drop the packet */
    return XDP_DROP;
}
}

char _license[] SEC("license") = "GPL"; // License of the code.
