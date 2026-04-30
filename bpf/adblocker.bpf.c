// SPDX-License-Identifier: MIT
//
// adblocker.bpf.c - TC egress + XDP ingress programs.
//
// Verifier-friendly patterns used throughout:
//   - every loop has a fixed `#pragma unroll` bound (MAX_QNAME=128,
//     MAX_LABELS=8). The suffix walk is bounded to 6 entries.
//   - data_end is rechecked after every pointer advance.
//   - bpf_ktime_get_ns is uptime, not wall-clock, so we DO NOT compare
//     domain_entry.expires_at against it in the kernel. Expiry is the
//     user-space reaper's job.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "maps.h"
#include "parsers.h"

char LICENSE[] SEC("license") = "MIT";

/* libbpf doesn't include linux/if_ether.h via vmlinux.h consistently; redefine. */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2
#endif

#ifndef XDP_PASS
#define XDP_PASS 2
#define XDP_DROP 1
#endif

/* struct ethhdr / iphdr / udphdr / tcphdr come from vmlinux.h - either
 * the BTF dump (production) or the placeholder shim (workstation build). */

static __always_inline void emit_event(__u8 reason, __u64 dh,
				       __u32 saddr, __u32 daddr,
				       __u16 sport, __u16 dport,
				       const char *qname, __u32 qlen)
{
	struct block_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	e->ts_ns       = bpf_ktime_get_ns();
	e->domain_hash = dh;
	e->saddr       = saddr;
	e->daddr       = daddr;
	e->sport       = sport;
	e->dport       = dport;
	e->reason      = reason;
	__builtin_memset(e->_pad, 0, sizeof(e->_pad));
	__builtin_memset(e->qname, 0, sizeof(e->qname));
	/* The volatile cast on the source defeats clang -O2's idiom
	 * recognizer, which would otherwise lower this byte loop to a
	 * call to __builtin_memcpy. The BPF target has no libc to link
	 * memcpy from, so that lowering breaks the build. */
	#pragma unroll
	for (int i = 0; i < MAX_QNAME; i++) {
		if ((__u32)i >= qlen)
			break;
		e->qname[i] = ((const volatile char *)qname)[i];
	}
	bpf_ringbuf_submit(e, 0);
}

static __always_inline int handle_dns(struct __sk_buff *skb, void *l4,
				      void *data_end, __u32 saddr, __u32 daddr,
				      __u16 sport, __u16 dport)
{
	/* l4 points at UDP header. DNS payload starts after 8-byte UDP hdr. */
	void *dns = l4 + sizeof(struct udphdr);
	if (dns + 12 > data_end)
		return TC_ACT_OK;

	/* skip 12-byte DNS header to QNAME */
	void *qname_start = dns + 12;
	if (qname_start >= data_end)
		return TC_ACT_OK;

	char name[MAX_QNAME] = {};
	__u64 hashes[MAX_LABELS];
	__u32 n_hashes = 0;

	int nlen = parse_qname(qname_start, data_end, name, MAX_QNAME, hashes, &n_hashes);
	if (nlen <= 0)
		return TC_ACT_OK;

	stat_inc(STAT_DNS_PARSED);

	__u64 dh = 0;
	struct domain_entry *de = NULL;
	if (!blocklist_lookup_hashes(hashes, n_hashes, &dh, &de))
		return TC_ACT_OK;

	if (de->flags & FLAG_ALLOW)
		return TC_ACT_OK;
	if (!(de->flags & FLAG_BLOCK))
		return TC_ACT_OK;

	stat_inc(STAT_BLOCKED_DNS);
	emit_event(REASON_DNS, dh, saddr, daddr, sport, dport, name, (__u32)nlen);
	return TC_ACT_SHOT;
}

static __always_inline int handle_tls(struct __sk_buff *skb, void *l4,
				      void *data_end, __u32 saddr, __u32 daddr,
				      __u16 sport, __u16 dport)
{
	struct tcphdr *tcp = l4;
	if ((void *)(tcp + 1) > data_end)
		return TC_ACT_OK;
	__u32 doff = (__u32)tcp->doff * 4;
	if (doff < sizeof(struct tcphdr))
		return TC_ACT_OK;
	void *payload = (void *)tcp + doff;
	if (payload + 5 > data_end)
		return TC_ACT_OK; /* not enough for a record header; nothing to do */

	char name[MAX_QNAME] = {};
	__u64 hashes[MAX_LABELS];
	__u32 n_hashes = 0;
	int nlen = parse_sni(payload, data_end, name, MAX_QNAME, hashes, &n_hashes);
	if (nlen <= 0)
		return TC_ACT_OK;

	stat_inc(STAT_SNI_PARSED);

	__u64 dh = 0;
	struct domain_entry *de = NULL;
	if (!blocklist_lookup_hashes(hashes, n_hashes, &dh, &de))
		return TC_ACT_OK;

	if (de->flags & FLAG_ALLOW)
		return TC_ACT_OK;
	if (!(de->flags & FLAG_BLOCK))
		return TC_ACT_OK;

	stat_inc(STAT_BLOCKED_SNI);
	emit_event(REASON_SNI, dh, saddr, daddr, sport, dport, name, (__u32)nlen);
	return TC_ACT_SHOT;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	stat_inc(STAT_PKTS_SEEN);

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK; /* IPv6 is a TODO. */

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return TC_ACT_OK;
	if (iph->ihl < 5)
		return TC_ACT_OK;
	void *l4 = (void *)iph + (__u32)iph->ihl * 4;
	if (l4 > data_end)
		return TC_ACT_OK;

	__u32 saddr = bpf_ntohl(iph->saddr);
	__u32 daddr = bpf_ntohl(iph->daddr);

	/* Layer 3: IP/CIDR backstop. */
	struct ipv4_lpm_key k = { .prefixlen = 32, .addr = iph->daddr };
	__u32 *hit = bpf_map_lookup_elem(&ip_blocklist, &k);
	if (hit) {
		stat_inc(STAT_BLOCKED_IP);
		emit_event(REASON_IP, 0, saddr, daddr, 0, 0, "", 0);
		return TC_ACT_SHOT;
	}

	if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return TC_ACT_OK;
		if (udp->dest == bpf_htons(53)) {
			__u16 sport = bpf_ntohs(udp->source);
			__u16 dport = bpf_ntohs(udp->dest);
			int act = handle_dns(skb, l4, data_end, saddr, daddr, sport, dport);
			if (act == TC_ACT_SHOT)
				return TC_ACT_SHOT;
		}
	} else if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return TC_ACT_OK;
		__u16 sport = bpf_ntohs(tcp->source);
		__u16 dport = bpf_ntohs(tcp->dest);
		if (tcp->dest == bpf_htons(443)) {
			int act = handle_tls(skb, l4, data_end, saddr, daddr, sport, dport);
			if (act == TC_ACT_SHOT)
				return TC_ACT_SHOT;
		}
		if (tcp->dest == bpf_htons(53)) {
			/* TCP/53 - DNS over TCP. The DNS msg is preceded by a
			 * 2-byte length. We don't bother parsing it for v1;
			 * the IP backstop and SNI handle most cases. */
		}
	}

	stat_inc(STAT_PASSED);
	return TC_ACT_OK;
}

SEC("xdp")
int xdp_ingress(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	struct ipv4_lpm_key k = { .prefixlen = 32, .addr = iph->saddr };
	__u32 *hit = bpf_map_lookup_elem(&ip_blocklist, &k);
	if (hit) {
		stat_inc(STAT_BLOCKED_IP);
		emit_event(REASON_IP, 0, bpf_ntohl(iph->saddr),
			   bpf_ntohl(iph->daddr), 0, 0, "", 0);
		return XDP_DROP;
	}
	return XDP_PASS;
}
