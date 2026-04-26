/* SPDX-License-Identifier: MIT */
/*
 * bpf/vmlinux.h - PLACEHOLDER.
 *
 * The real vmlinux.h is a multi-megabyte dump of every kernel type,
 * generated from the running kernel's BTF via:
 *
 *     make vmlinux
 *
 * which expands to:
 *
 *     bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
 *
 * Until you do that, this stub provides just enough types to make the
 * BPF source parse on a workstation that doesn't have BTF available -
 * `make vmlinux` will overwrite the file with the real thing before
 * `make build` is expected to succeed in production. CO-RE relocations
 * require the real vmlinux.h to function correctly.
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef signed char         __s8;
typedef unsigned char       __u8;
typedef short               __s16;
typedef unsigned short      __u16;
typedef int                 __s32;
typedef unsigned int        __u32;
typedef long long           __s64;
typedef unsigned long long  __u64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u16 __sum16;

/* sched_cls / TC sees an __sk_buff. */
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
};

/* XDP sees an xdp_md. */
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

#endif /* __VMLINUX_H__ */
