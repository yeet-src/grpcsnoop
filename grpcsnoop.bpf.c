// SPDX-License-Identifier: GPL-2.0
//
// grpcsnoop — capture plaintext gRPC/protobuf at the TC layer.
// Attaches SchedCls programs to a container's host-side veth via TCX
// (ingress + egress). Unlike a raw-tracepoint hook, the TC layer gives us
// `struct __sk_buff` + bpf_skb_load_bytes(), which reads the FULL TCP payload
// even when the skb is nonlinear (paged frags) — the case that defeats
// skb->data-based reads.
//
// Below TCP: each event is one segment's payload, tagged with 4-tuple + seq.
// Stream reassembly + HTTP/2 + gRPC framing happens in JS (tcpstream.js).
//
// Filtered by TCP port via `port_set` (populated from JS).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#define ETH_HLEN 14

#define TCX_NEXT (-1)   /* passive observer: run next prog / default-pass */

#define DATA_MAX 8192

#define DIR_EGRESS  0
#define DIR_INGRESS 1

struct port_val { __u8 v; };

struct seg_event {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 seq;
    __u8  dir;
    __u8  pad[3];
    __u32 total_len;
    __u32 captured;
    __u8  data[DATA_MAX];
};
__attribute__((used)) static const struct seg_event __seg_event_anchor;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct port_val);
    __uint(max_entries, 16);
} port_set SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 << 20);
} events SEC(".maps");

static __always_inline int port_tracked(__u16 port)
{
    __u32 k = port;
    return bpf_map_lookup_elem(&port_set, &k) != NULL;
}

static __always_inline int handle(struct __sk_buff *skb, __u8 dir)
{
    /* L2: require IPv4 */
    __u16 h_proto = 0;
    if (bpf_skb_load_bytes(skb, 12, &h_proto, sizeof(h_proto)) < 0)
        return TCX_NEXT;
    if (h_proto != bpf_htons(ETH_P_IP))
        return TCX_NEXT;

    /* L3: IPv4 header */
    __u8 vihl = 0, proto = 0;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &vihl, 1) < 0)
        return TCX_NEXT;
    __u32 ihl = (vihl & 0x0f) * 4;
    if (ihl < 20)
        return TCX_NEXT;
    if (bpf_skb_load_bytes(skb, ETH_HLEN + 9, &proto, 1) < 0)
        return TCX_NEXT;
    if (proto != IPPROTO_TCP)
        return TCX_NEXT;

    __u32 saddr = 0, daddr = 0;
    bpf_skb_load_bytes(skb, ETH_HLEN + 12, &saddr, 4);
    bpf_skb_load_bytes(skb, ETH_HLEN + 16, &daddr, 4);

    /* L4: TCP header (offset is runtime-variable; helper handles it) */
    __u32 l4 = ETH_HLEN + ihl;
    __u16 sport = 0, dport = 0;
    __u32 seq = 0;
    __u8  doffb = 0;
    bpf_skb_load_bytes(skb, l4,      &sport, 2);
    bpf_skb_load_bytes(skb, l4 + 2,  &dport, 2);
    bpf_skb_load_bytes(skb, l4 + 4,  &seq,   4);
    if (bpf_skb_load_bytes(skb, l4 + 12, &doffb, 1) < 0)
        return TCX_NEXT;
    __u32 doff = (doffb >> 4) * 4;
    if (doff < 20)
        return TCX_NEXT;

    sport = bpf_ntohs(sport);
    dport = bpf_ntohs(dport);
    if (!port_tracked(sport) && !port_tracked(dport))
        return TCX_NEXT;

    __u32 poff = l4 + doff;
    if (skb->len <= poff)
        return TCX_NEXT;                 /* no payload (pure ACK/SYN) */
    __u32 plen = skb->len - poff;

    __u32 cap = plen;
    if (cap > DATA_MAX)
        cap = DATA_MAX;
    cap &= (DATA_MAX - 1);               /* make the bound explicit for the verifier */
    if (cap == 0)
        return TCX_NEXT;

    struct seg_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return TCX_NEXT;
    e->saddr     = saddr;
    e->daddr     = daddr;
    e->sport     = sport;
    e->dport     = dport;
    e->seq       = bpf_ntohl(seq);
    e->dir       = dir;
    e->total_len = plen;
    e->captured  = cap;
    if (bpf_skb_load_bytes(skb, poff, e->data, cap) < 0) {
        bpf_ringbuf_discard(e, 0);
        return TCX_NEXT;
    }
    bpf_ringbuf_submit(e, 0);
    return TCX_NEXT;
}

SEC("tcx/ingress")
int on_ingress(struct __sk_buff *skb) { return handle(skb, DIR_INGRESS); }

SEC("tcx/egress")
int on_egress(struct __sk_buff *skb)  { return handle(skb, DIR_EGRESS); }

char LICENSE[] SEC("license") = "GPL";
