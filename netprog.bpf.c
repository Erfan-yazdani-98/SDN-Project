/* SPDX-License-Identifier: GPL-2.0 */
#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

//------------------------------------------------------------------------------
// Addition: Stats structures and maps for packet size analysis
//------------------------------------------------------------------------------
struct pkt_stats {
    __u64 total_bytes;
    __u64 packet_count;
};

// Global stats (key=0)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct pkt_stats);
    __uint(max_entries, 1);
} global_stats_map SEC(".maps");

// Protocol-based stats keyed by u16 Ethernet protocol
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, struct pkt_stats);
    __uint(max_entries, 256);
} proto_stats_map SEC(".maps");

#define ETH_P_IPV6       0x86DD  /* IPv6 */
#define IPPROTO_ICMPV6   58      /* ICMPv6 */

/* Byte-count bounds check */
#define __may_pull(start, off, end) \
    (((unsigned char *)(start)) + (off) <= ((unsigned char *)(end)))

#ifndef lock_xadd
#define lock_xadd(ptr, val)  ((void) __sync_fetch_and_add(ptr, val))
#endif

struct hdr_cursor { void *pos; };

//------------------------------------------------------------------------------
// Helper: record packet length into maps
static __always_inline void record_pkt_size(__u16 eth_proto, __u64 pkt_len) {
    // Update global stats
    __u32 gkey = 0;
    struct pkt_stats *g = bpf_map_lookup_elem(&global_stats_map, &gkey);
    if (g) {
        lock_xadd(&g->total_bytes, pkt_len);
        lock_xadd(&g->packet_count, 1);
    }

    // Update per-protocol stats
    struct pkt_stats *p = bpf_map_lookup_elem(&proto_stats_map, &eth_proto);
    if (!p) {
        struct pkt_stats zero = {};
        bpf_map_update_elem(&proto_stats_map, &eth_proto, &zero, BPF_NOEXIST);
        p = bpf_map_lookup_elem(&proto_stats_map, &eth_proto);
    }
    if (p) {
        lock_xadd(&p->total_bytes, pkt_len);
        lock_xadd(&p->packet_count, 1);
    }
}
//------------------------------------------------------------------------------

// Pass-through XDP program, now records packet sizes
SEC("xdp")
int xdp_prog_pass(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct hdr_cursor nh = { .pos = data };
    struct ethhdr *eth;
    int hdr_proto;
    __u16 eth_proto;

    // Parse Ethernet header
    hdr_proto = parse_ethhdr(&nh, data_end, &eth);
    if (hdr_proto < 0)
        return XDP_PASS;

    eth_proto = bpf_ntohs((__u16)hdr_proto);
    // Calculate packet length
    __u64 pkt_len = data_end - data;
    // Record stats
    record_pkt_size(eth_proto, pkt_len);

    return XDP_PASS;
}

//------------------------------------------------------------------------------
// ICMPv6 drop program, also records stats
static __always_inline int process_ipv6hdr(struct hdr_cursor *nh, void *data_end) {
    struct ipv6hdr *ip6h = nh->pos;
    int hdrsize = sizeof(*ip6h);
    if (!__may_pull(ip6h, hdrsize, data_end))
        return XDP_PASS;
    nh->pos += hdrsize;
    if (ip6h->nexthdr != IPPROTO_ICMPV6)
        return XDP_PASS;
    return XDP_DROP;
}

SEC("xdp")
int xdp_prog_drop_icmpv6(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct hdr_cursor nh = { .pos = data };
    struct ethhdr *eth;
    int hdr_proto;
    __u16 eth_proto;

    // Parse Ethernet header
    hdr_proto = parse_ethhdr(&nh, data_end, &eth);
    if (hdr_proto < 0)
        return XDP_PASS;
    eth_proto = bpf_ntohs((__u16)hdr_proto);

    // Calculate packet length
    __u64 pkt_len = data_end - data;
    // Record stats before potential drop
    record_pkt_size(eth_proto, pkt_len);

    // Drop ICMPv6
    int action = process_ipv6hdr(&nh, data_end);
    return action;
}

char _license[] SEC("license") = "Dual BSD/GPL";
