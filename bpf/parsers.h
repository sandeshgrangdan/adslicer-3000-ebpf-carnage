/* SPDX-License-Identifier: MIT */
#ifndef __ADBLOCKER_PARSERS_H__
#define __ADBLOCKER_PARSERS_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "maps.h"

/* FNV-1a 64-bit. Must produce byte-identical output to internal/hash. */
#define FNV1A_OFFSET 0xcbf29ce484222325ULL
#define FNV1A_PRIME  0x100000001b3ULL

static __always_inline __u64 fnv1a_lower(const char *buf, __u32 len)
{
	__u64 h = FNV1A_OFFSET;
	#pragma unroll
	for (int i = 0; i < MAX_QNAME; i++) {
		if ((__u32)i >= len)
			break;
		__u8 c = (__u8)buf[i];
		if (c >= 'A' && c <= 'Z')
			c += 32;
		h ^= c;
		h *= FNV1A_PRIME;
	}
	return h;
}

/*
 * Suffix walk. For "a.b.example.com" we hash the full name, then
 * "b.example.com", then "example.com", etc. Bounded to 6 entries on
 * the dot table to keep the verifier happy.
 *
 * `dots` is a list of byte offsets of every '.' in `name`, in order.
 * `n_dots` is how many we found (0..MAX_LABELS-1).
 */
static __always_inline int blocklist_suffix_hit(const char *name,
						__u32 len,
						const __u8 *dots,
						__u32 n_dots,
						__u64 *out_hash,
						struct domain_entry **out_entry)
{
	/* Full name first. */
	__u64 h = fnv1a_lower(name, len);
	struct domain_entry *e = bpf_map_lookup_elem(&blocklist, &h);
	if (e) {
		*out_hash = h;
		*out_entry = e;
		return 1;
	}

	/* Then progressively shorter suffixes. */
	#pragma unroll
	for (int i = 0; i < 6; i++) {
		if ((__u32)i >= n_dots)
			break;
		__u32 off = (__u32)dots[i] + 1;
		if (off >= len)
			break;
		__u32 sublen = len - off;
		if (sublen == 0 || sublen > MAX_QNAME)
			break;
		h = fnv1a_lower(name + off, sublen);
		e = bpf_map_lookup_elem(&blocklist, &h);
		if (e) {
			*out_hash = h;
			*out_entry = e;
			return 1;
		}
	}
	return 0;
}

/*
 * Parse a DNS QNAME from the byte stream at `cur`, with the packet
 * ending at `data_end`. Writes a flat lowercase dotted name (no
 * trailing dot) into `out`, returns its length, or -1 on malformed
 * input or compression pointers.
 */
static __always_inline int parse_qname(void *cur, void *data_end,
				       char *out, __u32 out_cap,
				       __u8 *dots, __u32 *n_dots_out)
{
	__u32 written = 0;
	__u32 n_dots = 0;
	__u8 *p = cur;

	#pragma unroll
	for (int label = 0; label < MAX_LABELS; label++) {
		if ((void *)(p + 1) > data_end)
			return -1;
		__u8 ll = *p++;
		if (ll == 0) {
			*n_dots_out = n_dots;
			return (int)written;
		}
		/* Compression pointers shouldn't appear in queries; bail. */
		if ((ll & 0xC0) != 0)
			return -1;
		if (ll > 63)
			return -1;
		if (label > 0) {
			if (written >= out_cap)
				return -1;
			out[written] = '.';
			if (n_dots < MAX_LABELS)
				dots[n_dots++] = (__u8)written;
			written++;
		}
		#pragma unroll
		for (int j = 0; j < 63; j++) {
			if ((__u32)j >= ll)
				break;
			if ((void *)(p + 1) > data_end)
				return -1;
			if (written >= out_cap)
				return -1;
			__u8 c = *p++;
			if (c >= 'A' && c <= 'Z')
				c += 32;
			out[written++] = (char)c;
		}
	}
	/* Ran out of labels without seeing terminator -> malformed. */
	return -1;
}

/*
 * Parse a TLS ClientHello and locate the SNI extension's hostname.
 * `cur` points at the first byte of TCP payload. On success writes the
 * server_name into `out` and returns its length; -1 otherwise.
 *
 * Layout (RFC 5246 / RFC 8446):
 *   record:    type(1)=0x16 ver(2) len(2)
 *   handshake: type(1)=0x01 len(3)
 *   client_hello: ver(2) random(32) sid(1+n) ciphers(2+n) comp(1+n) ext(2+n)
 *   extension: type(2) len(2) data(len)
 *   sni ext:   list_len(2) name_type(1)=0 name_len(2) name(name_len)
 */
static __always_inline int parse_sni(void *cur, void *data_end,
				     char *out, __u32 out_cap,
				     __u8 *dots, __u32 *n_dots_out)
{
	__u8 *p = cur;

	/* TLS record header */
	if ((void *)(p + 5) > data_end) return -1;
	if (p[0] != 0x16) return -1; /* not Handshake */
	p += 5;

	/* Handshake header */
	if ((void *)(p + 4) > data_end) return -1;
	if (p[0] != 0x01) return -1; /* not ClientHello */
	p += 4;

	/* client_version + random */
	if ((void *)(p + 2 + 32) > data_end) return -1;
	p += 2 + 32;

	/* session_id */
	if ((void *)(p + 1) > data_end) return -1;
	__u8 sid_len = p[0];
	p += 1;
	if ((void *)(p + sid_len) > data_end) return -1;
	p += sid_len;

	/* cipher_suites */
	if ((void *)(p + 2) > data_end) return -1;
	__u16 cs_len = (__u16)((p[0] << 8) | p[1]);
	p += 2;
	if ((void *)(p + cs_len) > data_end) return -1;
	p += cs_len;

	/* compression_methods */
	if ((void *)(p + 1) > data_end) return -1;
	__u8 cm_len = p[0];
	p += 1;
	if ((void *)(p + cm_len) > data_end) return -1;
	p += cm_len;

	/* extensions */
	if ((void *)(p + 2) > data_end) return -1;
	__u16 ext_total = (__u16)((p[0] << 8) | p[1]);
	p += 2;

	__u8 *ext_end = p + ext_total;
	if ((void *)ext_end > data_end) ext_end = data_end;

	#pragma unroll
	for (int i = 0; i < 16; i++) {
		if ((void *)(p + 4) > ext_end) return -1;
		__u16 etype = (__u16)((p[0] << 8) | p[1]);
		__u16 elen  = (__u16)((p[2] << 8) | p[3]);
		p += 4;
		if ((void *)(p + elen) > ext_end) return -1;

		if (etype == 0x0000) {
			/* server_name extension */
			if (elen < 5) return -1;
			__u8 *q = p;
			/* server_name_list length (2) */
			q += 2;
			/* name_type (1) */
			if ((void *)(q + 1) > data_end) return -1;
			if (q[0] != 0) return -1; /* not host_name */
			q += 1;
			/* host_name length (2) */
			if ((void *)(q + 2) > data_end) return -1;
			__u16 nlen = (__u16)((q[0] << 8) | q[1]);
			q += 2;
			if (nlen == 0 || nlen > out_cap) return -1;
			if ((void *)(q + nlen) > data_end) return -1;

			__u32 written = 0;
			__u32 n_dots = 0;
			#pragma unroll
			for (int j = 0; j < MAX_QNAME; j++) {
				if ((__u32)j >= (__u32)nlen)
					break;
				__u8 c = q[j];
				if (c >= 'A' && c <= 'Z')
					c += 32;
				if (c == '.' && n_dots < MAX_LABELS)
					dots[n_dots++] = (__u8)written;
				out[written++] = (char)c;
			}
			*n_dots_out = n_dots;
			return (int)written;
		}
		p += elen;
	}
	return -1;
}

#endif /* __ADBLOCKER_PARSERS_H__ */
