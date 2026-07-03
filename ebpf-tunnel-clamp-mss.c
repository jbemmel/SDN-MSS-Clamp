#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Fallback clamp targets, used only when the runtime MTU cannot be queried
 * (kernels older than 5.12). They match a VXLAN overlay interface (MTU 1450).
 * When bpf_check_mtu() is available the targets are derived from the real
 * egress-device MTU, which makes the program correct for VXLAN, WireGuard, or
 * any other tunnel without hard-coding per-tunnel overhead. */
#define FALLBACK_MSS_IPV4 1410
#define FALLBACK_MSS_IPV6 1390

#define TCP_HDR_LEN 20
#define TCP_OPT_MSS 2
#define TCP_OPT_MSS_LEN 4

/* Maximum number of TCP options we are willing to walk (bounds the unrolled
 * loop for the verifier). */
#define MAX_TCP_OPTS 10

/* VXLAN encapsulation (RFC 7348): outer UDP -> 8-byte VXLAN header -> a full
 * inner Ethernet frame. When the program is attached to the *underlay* device
 * (e.g. a transit router forwarding encapsulated traffic) the TCP SYN we want
 * to clamp lives inside this stack, so we descend into it. */
#define UDP_HDR_LEN 8
#define VXLAN_HDR_LEN 8
#define VXLAN_FLAG_VNI 0x08          /* header 'I' flag: the VNI field is valid */
#define VXLAN_PORT_IANA 4789         /* IANA-assigned VXLAN port (EVPN default)  */
#define VXLAN_PORT_LINUX 8472        /* Linux default when dstport is unset      */

/* parse_ip() return codes. */
#define PARSE_OK 0
#define PARSE_SHORT (-1)             /* packet too short for the L3 header       */
#define PARSE_BADVER (-2)            /* IP version nibble mismatch               */
#define PARSE_NOTIP (-3)            /* EtherType is neither IPv4 nor IPv6        */

/* Per-branch statistics counters. Each value indexes the mss_stats per-CPU
 * array below; keep STAT_MAX last so it sizes the map automatically. User space
 * can dump the map (e.g. `bpftool map dump name mss_stats`) and sum the per-CPU
 * values to see how many packets took each path. */
enum mss_stat {
    STAT_TOTAL = 0,      /* every packet entering the program                */
    STAT_MTU_FALLBACK,   /* bpf_check_mtu() unavailable/failed -> fallback   */
    STAT_L2_HEADER,      /* Ethernet header detected and skipped             */
    STAT_IPV4,           /* parsed as IPv4                                   */
    STAT_IPV6,           /* parsed as IPv6                                   */
    STAT_NON_IP,         /* neither IPv4 nor IPv6                            */
    STAT_SHORT_L3,       /* packet too short for the L3 header               */
    STAT_BAD_VERSION,    /* IP version nibble mismatch (mis-detected offset) */
    STAT_NON_TCP,        /* L4 protocol is not TCP                           */
    STAT_SHORT_L4,       /* packet too short for the TCP header              */
    STAT_NON_SYN,        /* not a SYN, so no MSS option to clamp             */
    STAT_BAD_TCP_OPTS,   /* TCP data offset malformed / no options present   */
    STAT_OPT_END,        /* reached End-of-Options before finding MSS        */
    STAT_OPT_NOOP,       /* skipped a No-Op option                           */
    STAT_OPT_BAD_LEN,    /* malformed option length                          */
    STAT_MSS_FOUND,      /* located a well-formed MSS option                 */
    STAT_MSS_SHORT,      /* MSS option value truncated at packet end         */
    STAT_CLAMPED,        /* MSS lowered to the target                        */
    STAT_ALREADY_OK,     /* MSS already <= target, left unchanged            */
    STAT_VXLAN,          /* VXLAN frame detected; descended to the inner TCP */
    STAT_MAX,            /* keep last: number of counters                    */
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STAT_MAX);
} mss_stats SEC(".maps");

/* Increment a per-CPU branch counter. Per-CPU storage means a plain add is
 * race-free without atomics. */
static __always_inline void stat_inc(enum mss_stat key) {
    __u32 index = key;
    __u64 *val = bpf_map_lookup_elem(&mss_stats, &index);
    if (val)
        *val += 1;
}

/* Derive the MSS budget from the device MTU (an L3 value). The MSS is the MTU
 * minus the L3 header and the fixed TCP header. Falls back to the compile-time
 * default when the MTU is unknown (mtu == 0) or implausibly small. */
static __always_inline __u16 mss_from_mtu(__u32 mtu, __u16 l3_hdr_len, __u16 fallback) {
    __u32 overhead = (__u32)l3_hdr_len + TCP_HDR_LEN;
    if (mtu > overhead)
        return (__u16)(mtu - overhead);
    return fallback;
}

/* Parse an IPv4 or IPv6 header located at byte offset `off`. On success returns
 * PARSE_OK and fills in the L4 protocol and the L3 header length; otherwise a
 * negative PARSE_* code. Used for both the outer header and, for VXLAN, the
 * encapsulated inner header. */
static __always_inline int parse_ip(struct __sk_buff *skb, __u32 off, __u16 l3_proto,
                                    __u8 *l4_proto, __u16 *l3_hdr_len) {
    if (l3_proto == ETH_P_IP) {
        __u8 ver_ihl = 0;
        __u8 proto = 0;
        if (bpf_skb_load_bytes(skb, off, &ver_ihl, sizeof(ver_ihl)) < 0)
            return PARSE_SHORT;
        if ((ver_ihl >> 4) != 4)                   /* mis-detected offset guard */
            return PARSE_BADVER;
        if (bpf_skb_load_bytes(skb, off + __builtin_offsetof(struct iphdr, protocol),
                               &proto, sizeof(proto)) < 0)
            return PARSE_SHORT;
        *l4_proto = proto;
        *l3_hdr_len = (__u16)(ver_ihl & 0x0f) * 4; /* IHL is in 32-bit words     */
        return PARSE_OK;
    }
    if (l3_proto == ETH_P_IPV6) {
        __u8 ver = 0;
        __u8 nexthdr = 0;
        if (bpf_skb_load_bytes(skb, off, &ver, sizeof(ver)) < 0)
            return PARSE_SHORT;
        if ((ver >> 4) != 6)
            return PARSE_BADVER;
        /* Only clamp when TCP follows directly; IPv6 extension headers are not
         * walked (uncommon for handshakes and left to PMTUD). */
        if (bpf_skb_load_bytes(skb, off + __builtin_offsetof(struct ipv6hdr, nexthdr),
                               &nexthdr, sizeof(nexthdr)) < 0)
            return PARSE_SHORT;
        *l4_proto = nexthdr;
        *l3_hdr_len = sizeof(struct ipv6hdr);
        return PARSE_OK;
    }
    return PARSE_NOTIP;
}

/* This program parses and rewrites packets purely through byte offsets using
 * bpf_skb_load_bytes()/bpf_skb_store_bytes(). Those helpers perform their own
 * runtime bounds checks, so - unlike direct packet-pointer walking - the
 * verifier stays happy even with the variable-length IPv4 header and the
 * variable TCP option region. */
SEC("tc")
int clamp_mss_egress(struct __sk_buff *skb) {
    stat_inc(STAT_TOTAL);

    /* Egress device MTU (L3). On success dev_mtu is e.g. 1420 (WireGuard) or
     * 1450 (VXLAN); on older kernels the helper fails and we use fallbacks. */
    __u32 dev_mtu = 0;
    if (bpf_check_mtu(skb, 0, &dev_mtu, 0, 0) < 0) {
        dev_mtu = 0;
        stat_inc(STAT_MTU_FALLBACK);
    }

    /* skb->protocol carries the L3 EtherType whether or not the device has a
     * link layer. WireGuard (and other tun devices) are pure L3. */
    __u16 l3_proto = bpf_ntohs(skb->protocol);

    /* Skip an Ethernet header only when one is actually present. We detect it
     * by matching the frame EtherType (bytes 12-13) against skb->protocol; a
     * pure L3 tun device has no such header, so l3_off stays 0. */
    __u32 l3_off = 0;
    __u16 eth_proto = 0;
    if ((l3_proto == ETH_P_IP || l3_proto == ETH_P_IPV6) &&
        bpf_skb_load_bytes(skb, __builtin_offsetof(struct ethhdr, h_proto),
                           &eth_proto, sizeof(eth_proto)) == 0 &&
        bpf_ntohs(eth_proto) == l3_proto) {
        l3_off = sizeof(struct ethhdr);
        stat_inc(STAT_L2_HEADER);
    }

    __u32 l4_off = 0;
    __u16 target_mss = 0;

    /* For VXLAN we clamp the inner TCP MSS; `is_inner` records that so the clamp
     * site also repairs the outer UDP checksum at `outer_udp_off`. */
    int is_inner = 0;
    __u32 outer_udp_off = 0;

    /* Parse the outer IP header. */
    __u8 outer_proto = 0;
    __u16 outer_ip_hdr = 0;
    int rc = parse_ip(skb, l3_off, l3_proto, &outer_proto, &outer_ip_hdr);
    if (rc == PARSE_SHORT) {
        stat_inc(STAT_SHORT_L3);
        return TC_ACT_OK;
    }
    if (rc == PARSE_BADVER) {
        stat_inc(STAT_BAD_VERSION);
        return TC_ACT_OK;
    }
    if (rc == PARSE_NOTIP) {
        stat_inc(STAT_NON_IP);
        return TC_ACT_OK;
    }
    stat_inc(l3_proto == ETH_P_IP ? STAT_IPV4 : STAT_IPV6);

    if (outer_proto == IPPROTO_TCP) {
        /* Bare TCP: clamp against the egress-device MTU directly. */
        l4_off = l3_off + outer_ip_hdr;
        target_mss = (l3_proto == ETH_P_IP)
                         ? mss_from_mtu(dev_mtu, sizeof(struct iphdr), FALLBACK_MSS_IPV4)
                         : mss_from_mtu(dev_mtu, sizeof(struct ipv6hdr), FALLBACK_MSS_IPV6);

    } else if (outer_proto == IPPROTO_UDP) {
        /* Might be VXLAN. Confirm via the destination port and the VXLAN 'I'
         * flag before descending into the encapsulated inner frame. */
        outer_udp_off = l3_off + outer_ip_hdr;

        __u16 dport = 0;
        if (bpf_skb_load_bytes(skb, outer_udp_off + __builtin_offsetof(struct udphdr, dest),
                               &dport, sizeof(dport)) < 0) {
            stat_inc(STAT_SHORT_L4);
            return TC_ACT_OK;
        }
        dport = bpf_ntohs(dport);

        __u32 vxlan_off = outer_udp_off + UDP_HDR_LEN;
        __u8 vx_flags = 0;
        if ((dport != VXLAN_PORT_IANA && dport != VXLAN_PORT_LINUX) ||
            bpf_skb_load_bytes(skb, vxlan_off, &vx_flags, sizeof(vx_flags)) < 0 ||
            !(vx_flags & VXLAN_FLAG_VNI)) {
            stat_inc(STAT_NON_TCP);              /* plain UDP, nothing to clamp */
            return TC_ACT_OK;
        }
        stat_inc(STAT_VXLAN);
        is_inner = 1;

        /* Inner L2: VXLAN always carries a complete Ethernet frame. */
        __u32 inner_eth_off = vxlan_off + VXLAN_HDR_LEN;
        __u16 inner_proto = 0;
        if (bpf_skb_load_bytes(skb, inner_eth_off + __builtin_offsetof(struct ethhdr, h_proto),
                               &inner_proto, sizeof(inner_proto)) < 0) {
            stat_inc(STAT_SHORT_L3);
            return TC_ACT_OK;
        }
        inner_proto = bpf_ntohs(inner_proto);
        __u32 inner_l3_off = inner_eth_off + sizeof(struct ethhdr);

        __u8 inner_l4_proto = 0;
        __u16 inner_ip_hdr = 0;
        int ri = parse_ip(skb, inner_l3_off, inner_proto, &inner_l4_proto, &inner_ip_hdr);
        if (ri == PARSE_SHORT) {
            stat_inc(STAT_SHORT_L3);
            return TC_ACT_OK;
        }
        if (ri == PARSE_BADVER) {
            stat_inc(STAT_BAD_VERSION);
            return TC_ACT_OK;
        }
        if (ri == PARSE_NOTIP) {
            stat_inc(STAT_NON_IP);
            return TC_ACT_OK;
        }
        stat_inc(inner_proto == ETH_P_IP ? STAT_IPV4 : STAT_IPV6);
        if (inner_l4_proto != IPPROTO_TCP) {
            stat_inc(STAT_NON_TCP);
            return TC_ACT_OK;
        }

        l4_off = inner_l3_off + inner_ip_hdr;
        /* Budget subtracts the whole encapsulation: outer IP + UDP + VXLAN +
         * inner Ethernet + inner IP (the fixed TCP header is added by the
         * helper). This makes the inner endpoints advertise an MSS whose
         * encapsulated packet still fits the underlay MTU. */
        __u16 overhead = outer_ip_hdr + UDP_HDR_LEN + VXLAN_HDR_LEN +
                         sizeof(struct ethhdr) + inner_ip_hdr;
        target_mss = mss_from_mtu(dev_mtu, overhead,
                                  inner_proto == ETH_P_IP ? FALLBACK_MSS_IPV4
                                                          : FALLBACK_MSS_IPV6);
    } else {
        stat_inc(STAT_NON_TCP);
        return TC_ACT_OK;
    }

    /* TCP data offset (high nibble of byte 12) and flags (byte 13). */
    __u16 doff_flags = 0;
    if (bpf_skb_load_bytes(skb, l4_off + 12, &doff_flags, sizeof(doff_flags)) < 0) {
        stat_inc(STAT_SHORT_L4);
        return TC_ACT_OK;
    }
    doff_flags = bpf_ntohs(doff_flags);

    /* Only initial handshake packets (SYN, bit 0x02 of the flags byte) carry an
     * MSS option worth clamping. */
    if (!(doff_flags & 0x02)) {
        stat_inc(STAT_NON_SYN);
        return TC_ACT_OK;
    }

    __u8 doff = (doff_flags >> 12) & 0x0f;         /* header length in 32-bit words */
    __u32 opt_off = l4_off + TCP_HDR_LEN;
    __u32 opt_end = l4_off + (__u32)doff * 4;
    if (doff < 5 || opt_end <= opt_off) {          /* no options present */
        stat_inc(STAT_BAD_TCP_OPTS);
        return TC_ACT_OK;
    }

    /* Walk the TCP options looking for the MSS option (kind 2, length 4). */
    #pragma unroll
    for (int i = 0; i < MAX_TCP_OPTS; i++) {
        if (opt_off + 1 > opt_end)
            break;

        __u8 kind = 0;
        if (bpf_skb_load_bytes(skb, opt_off, &kind, sizeof(kind)) < 0)
            break;

        if (kind == 0) {                           /* End of Option List */
            stat_inc(STAT_OPT_END);
            break;
        }
        if (kind == 1) {                           /* No-Op */
            stat_inc(STAT_OPT_NOOP);
            opt_off += 1;
            continue;
        }

        if (opt_off + 2 > opt_end) {
            stat_inc(STAT_OPT_BAD_LEN);
            break;
        }
        __u8 olen = 0;
        if (bpf_skb_load_bytes(skb, opt_off + 1, &olen, sizeof(olen)) < 0)
            break;
        if (olen < 2 || opt_off + olen > opt_end) {
            stat_inc(STAT_OPT_BAD_LEN);
            break;
        }

        if (kind == TCP_OPT_MSS && olen == TCP_OPT_MSS_LEN) {
            __u16 mss_net = 0;
            if (bpf_skb_load_bytes(skb, opt_off + 2, &mss_net, sizeof(mss_net)) < 0) {
                stat_inc(STAT_MSS_SHORT);
                break;
            }
            stat_inc(STAT_MSS_FOUND);

            /* Clamp downward only if the advertised MSS exceeds our budget. */
            if (bpf_ntohs(mss_net) > target_mss) {
                __u16 new_net = bpf_htons(target_mss);

                /* Debug only: writes to the kernel trace pipe. Watch it with
                 * `bpftool prog tracelog` or
                 * `cat /sys/kernel/debug/tracing/trace_pipe`. Remove for prod. */
                bpf_printk("mss-clamp: old=%u new=%u\n", bpf_ntohs(mss_net), target_mss);

                /* Incrementally fix the TCP checksum for the 2 changed bytes,
                 * then write the new MSS value. */
                bpf_l4_csum_replace(skb, l4_off + __builtin_offsetof(struct tcphdr, check),
                                    mss_net, new_net, sizeof(new_net));
                bpf_skb_store_bytes(skb, opt_off + 2, &new_net, sizeof(new_net), 0);

                /* For VXLAN the outer UDP checksum also covers the inner bytes we
                 * just changed, so repair it when present. A zero UDP checksum
                 * means "disabled" (common for VXLAN) and is left as-is;
                 * BPF_F_MARK_MANGLED_0 stops a freshly computed 0 from being
                 * misread as "disabled". */
                if (is_inner) {
                    __u16 udp_csum = 0;
                    __u32 udp_csum_off = outer_udp_off + __builtin_offsetof(struct udphdr, check);
                    if (bpf_skb_load_bytes(skb, udp_csum_off, &udp_csum, sizeof(udp_csum)) == 0 &&
                        udp_csum != 0) {
                        bpf_l4_csum_replace(skb, udp_csum_off, mss_net, new_net,
                                            sizeof(new_net) | BPF_F_MARK_MANGLED_0);
                    }
                }
                stat_inc(STAT_CLAMPED);
            } else {
                stat_inc(STAT_ALREADY_OK);
            }
            break;
        }

        opt_off += olen;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
