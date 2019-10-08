#include <linux/kconfig.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/ptrace.h>
#pragma clang diagnostic pop
#include <linux/bpf.h>
#include <linux/version.h>

#include "bpf_helpers.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Wenum-conversion"
#include <net/sock.h>
#pragma clang diagnostic pop
#include <net/inet_sock.h>
#include <net/net_namespace.h>

#define IP_TCP 6
#define ETH_HLEN 14

struct iphdr {
    u8    ihlver;
    u8    tos;
    u16    tot_len;
    u16    id;
    u16    frag_off;
    u8    ttl;
    u8    protocol;
    u16    check;
    u32    saddr;
    u32    daddr;
};

struct FlowRecord {
    u32 srcip;
    u32 dstip;
    u16 srcport;
    u16 dstport;
};

struct bpf_map_def SEC("maps/sessions") sessions = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct FlowRecord),
    .value_size = sizeof(u8),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

static inline void reverse_flow(struct FlowRecord *flow, struct FlowRecord *reverse) {
    reverse->srcip = flow->dstip;
    reverse->dstip = flow->srcip;
    reverse->srcport = flow->dstport;
    reverse->dstport = flow->srcport;
}

static inline void bpf_key_delete(struct bpf_map_def *map, struct FlowRecord *flow) {
    struct FlowRecord reverse;

    reverse_flow(flow, &reverse);

    bpf_map_delete_elem(map, flow);
    bpf_map_delete_elem(map, &reverse);
}

static inline bool bpf_key_exists(struct bpf_map_def *map, struct FlowRecord *flow) {
    struct FlowRecord reverse;

    reverse_flow(flow, &reverse);

    if (bpf_map_lookup_elem(&sessions, flow)) {
        return true;
     }

    if (bpf_map_lookup_elem(map, &reverse)) {
        return true;
    }

    return false;
}

static inline void bpf_key_update(struct bpf_map_def *map, struct FlowRecord *flow) {
    struct FlowRecord reverse;
    u8 val = 1;

    reverse_flow(flow, &reverse);

    bpf_map_update_elem(map, flow, &val, BPF_ANY);
    bpf_map_update_elem(map, &reverse, &val, BPF_ANY);
}

SEC("socket/app_ack")
int app_ack(struct __sk_buff *skb) {
    struct FlowRecord key;

    key.srcip = load_word(skb, offsetof(struct iphdr, saddr));
    key.dstip = load_word(skb, offsetof(struct iphdr, daddr));
    key.srcport = load_half(skb, sizeof(struct iphdr));
    key.dstport = load_half(skb, sizeof(struct iphdr)+2);

    if (bpf_key_exists(&sessions, &key)) {
        return 0;
    }

    return -1;
}

