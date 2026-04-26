/* SPDX-License-Identifier: MIT */
#ifndef __ADBLOCKER_MAPS_H__
#define __ADBLOCKER_MAPS_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* Flags on a domain_entry. */
#define FLAG_BLOCK 1
#define FLAG_ALLOW 2
#define FLAG_TEMP  4

/* Reasons emitted in block_event.reason. */
#define REASON_DNS 1
#define REASON_SNI 2
#define REASON_IP  3

/* Stats slots - keep in sync with Go side. */
#define STAT_PKTS_SEEN   0
#define STAT_DNS_PARSED  1
#define STAT_SNI_PARSED  2
#define STAT_BLOCKED_DNS 3
#define STAT_BLOCKED_SNI 4
#define STAT_BLOCKED_IP  5
#define STAT_PASSED      6
#define STAT__MAX        7

#define MAX_QNAME  128   /* DNS limit is 255 but most names < 128; kept small for verifier. */
#define MAX_LABELS 8     /* Bound for the per-name label loop; suffix walk uses 6. */

struct domain_entry {
	__u8  flags;
	__u8  _pad[7];
	__u64 expires_at; /* unix nanoseconds; 0 means never expires (set by user-space reaper) */
};

struct block_event {
	__u64 ts_ns;
	__u64 domain_hash;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8  reason;
	__u8  _pad[7];
	char  qname[MAX_QNAME];
};

/* {prefixlen, addr} for the LPM trie. */
struct ipv4_lpm_key {
	__u32 prefixlen;
	__u32 addr; /* network byte order */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key,   __u64);
	__type(value, struct domain_entry);
	__uint(max_entries, 1 << 20);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} blocklist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key,   struct ipv4_lpm_key);
	__type(value, __u32);
	__uint(max_entries, 1 << 16);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_blocklist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key,   __u32);
	__type(value, __u64);
	__uint(max_entries, STAT__MAX);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps");

static __always_inline void stat_inc(__u32 slot)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &slot);
	if (v)
		__sync_fetch_and_add(v, 1);
}

#endif /* __ADBLOCKER_MAPS_H__ */
