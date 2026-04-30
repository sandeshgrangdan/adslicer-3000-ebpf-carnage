/* SPDX-License-Identifier: MIT */
#ifndef __ADBLOCKER_PARSERS_H__
#define __ADBLOCKER_PARSERS_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "maps.h"

/* FNV-1a 64-bit. Must produce byte-identical output to internal/hash. */
#define FNV1A_OFFSET 0xcbf29ce484222325ULL
#define FNV1A_PRIME  0x100000001b3ULL

/*
 * Read a big-endian u16, then bound-mask. Two verifier issues are
 * addressed at once:
 *   1. clang lowers `(p[0] << 8) | p[1]` through int promotion and
 *      the kernel verifier on Linux 6.x loses scalar-bound tracking
 *      across the `|`, leaving the result as an unbounded scalar.
 *      Any subsequent `pkt_ptr + result` is rejected with "math
 *      between pkt pointer and register with unbounded min value".
 *      The asm barrier + 0xffff mask re-establishes the [0, 65535]
 *      bound.
 *   2. Once we do `p += cs_len` (a value up to 65535), the resulting
 *      packet pointer has `var_off=(0x0; 0xffff)` and the verifier
 *      cannot derive a readable-byte bound from a subsequent
 *      `(p + 1) > data_end` check — even though such a check is
 *      logically sufficient. We don't actually need 16-bit lengths
 *      in any TLS field we touch (real-world cs_len, ext_total,
 *      elen, nlen are all < 4096), so callers further mask to a
 *      smaller bound (`& 0xfff` etc.) to give the verifier a tight
 *      var_off it can propagate. Real handshakes don't exceed those
 *      caps; pathological ones get parse_sni == -1, same as malformed.
 */
static __always_inline __u32 read_be16(const __u8 *p)
{
	__u32 hi = (__u32)p[0];
	__u32 lo = (__u32)p[1];
	__u32 v = (hi << 8) | lo;
	asm volatile ("" : "+r"(v));
	return v & 0xffff;
}

/*
 * Look up each precomputed FNV-1a hash in the blocklist map and stop at
 * the first hit. The hash array is laid out as `hashes[0]` = full-name
 * hash, then progressively shorter suffix hashes. `n_hashes` is the
 * number of slots populated by parse_qname / parse_sni (1 + n_dots).
 */
static __always_inline int blocklist_lookup_hashes(const __u64 *hashes, __u32 n_hashes,
						   __u64 *out_hash,
						   struct domain_entry **out_entry)
{
	#pragma unroll
	for (int i = 0; i < MAX_LABELS; i++) {
		if ((__u32)i >= n_hashes)
			break;
		struct domain_entry *e = bpf_map_lookup_elem(&blocklist, &hashes[i]);
		if (e) {
			*out_hash = hashes[i];
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
 *
 * Hashes are computed *during* parsing: hashes[0] is the full-name
 * FNV-1a, hashes[1..n] are progressively shorter suffix hashes (each
 * starting at the byte after the i-th dot). This avoids a second
 * pass that re-reads `out` with runtime offsets — a pattern the
 * kernel verifier rejects on Linux 6.8 (variable-offset stack reads
 * cause the verifier to either reject or blow past its 1M-instruction
 * complexity budget when called repeatedly for each suffix).
 *
 * `hashes` must point to MAX_LABELS u64 slots; `n_hashes_out` receives
 * 1 + (number of dots written), capped at MAX_LABELS.
 */
static __always_inline int parse_qname(void *cur, void *data_end,
				       char *out, __u32 out_cap,
				       __u64 *hashes, __u32 *n_hashes_out)
{
	__u8 *base = cur;
	__u32 written = 0;
	__u32 n_hashes = 1;
	__u32 labels_seen = 0;
	__u32 remaining = 0;
	__u8 need_dot = 0;
	__u8 just_saw_dot = 0;

	/* Pre-init every hash slot. We "activate" a new suffix hash by
	 * incrementing n_hashes — no variable-offset write needed. */
	#pragma unroll
	for (int k = 0; k < MAX_LABELS; k++)
		hashes[k] = FNV1A_OFFSET;

	#pragma unroll
	for (int i = 0; i < MAX_QNAME; i++) {
		if ((void *)(base + i + 1) > data_end)
			return -1;
		__u8 b = base[i];

		__u8 emit_byte = 0;
		__u8 emitted = 0;

		if (remaining == 0) {
			/* length byte (or terminator) */
			if (b == 0) {
				*n_hashes_out = n_hashes;
				return (int)written;
			}
			/* compression pointers shouldn't appear in queries */
			if ((b & 0xC0) != 0)
				return -1;
			if (b > 63)
				return -1;
			if (labels_seen >= MAX_LABELS - 1)
				return -1;
			if (need_dot) {
				if (written >= out_cap)
					return -1;
				out[written++] = '.';
				emit_byte = '.';
				emitted = 1;
				just_saw_dot = 1;
			}
			labels_seen++;
			remaining = b;
			need_dot = 1;
		} else {
			/* content byte */
			if (written >= out_cap)
				return -1;
			__u8 c = b;
			if (c >= 'A' && c <= 'Z')
				c += 32;
			out[written++] = (char)c;

			/* Activate a fresh suffix slot on the byte after a '.'. */
			if (just_saw_dot) {
				if (n_hashes < MAX_LABELS) {
					hashes[n_hashes] = FNV1A_OFFSET;
					n_hashes++;
				}
				just_saw_dot = 0;
			}

			emit_byte = c;
			emitted = 1;
			remaining--;
		}

		/* Unconditional update of every slot. Slots past n_hashes
		 * receive garbage updates but are never read (the lookup
		 * walks only 0..n_hashes), so the values don't matter; in
		 * exchange we save the verifier from forking once per slot
		 * every byte. The just-activated slot was reset to OFFSET
		 * above. */
		if (emitted) {
			hashes[0] = (hashes[0] ^ emit_byte) * FNV1A_PRIME;
			hashes[1] = (hashes[1] ^ emit_byte) * FNV1A_PRIME;
			hashes[2] = (hashes[2] ^ emit_byte) * FNV1A_PRIME;
			hashes[3] = (hashes[3] ^ emit_byte) * FNV1A_PRIME;
		}
	}
	/* Ran past MAX_QNAME without seeing a terminator -> malformed. */
	return -1;
}

/*
 * Parse a TLS ClientHello and locate the SNI extension's hostname.
 * `cur` points at the first byte of TCP payload. On success writes the
 * server_name into `out`, fills `hashes[0..n_hashes_out)` with the
 * full-name hash followed by suffix hashes (same shape as parse_qname),
 * and returns the name's length; -1 otherwise.
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
				     __u64 *hashes, __u32 *n_hashes_out)
{
	/*
	 * SNI parsing is temporarily disabled for v0.1.1 because the
	 * extension-walking loop accumulates packet-pointer var_off
	 * across iterations, and the kernel verifier on Linux 6.8
	 * cannot prove subsequent reads are in-bounds. The whole
	 * function is gated here so handle_tls() compiles unchanged
	 * but always returns TC_ACT_OK. SNI blocking will be restored
	 * in a follow-up release that restructures the parser around
	 * a per-cpu scratch map (variable-offset reads from map values
	 * are accepted by the verifier where stack reads are not).
	 *
	 * DNS blocking via parse_qname / handle_dns is unaffected.
	 */
	(void)cur; (void)data_end; (void)out; (void)out_cap;
	(void)hashes; (void)n_hashes_out;
	return -1;

	/* Unreachable below — kept as a reference for the follow-up. */
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
	__u32 cs_len = read_be16(p);
	if (cs_len > 0xfff) return -1;   /* see read_be16 comment */
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
	__u32 ext_total = read_be16(p);
	if (ext_total > 0xfff) return -1;   /* see read_be16 comment */
	p += 2;

	__u8 *ext_end = p + ext_total;
	if ((void *)ext_end > data_end) ext_end = data_end;

	#pragma unroll
	for (int i = 0; i < 16; i++) {
		if (p + 4 > ext_end) return -1;
		__u32 etype = read_be16(p);
		__u32 elen  = read_be16(p + 2);
		if (elen > 0xfff) return -1;   /* see read_be16 comment */
		p += 4;
		if (p + elen > ext_end) return -1;

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
			__u32 nlen = read_be16(q);
			if (nlen == 0 || nlen > out_cap) return -1;
			q += 2;
			if ((void *)(q + nlen) > data_end) return -1;

			__u32 written = 0;
			__u32 n_hashes = 1;
			__u8 just_saw_dot = 0;

			/* Pre-init like parse_qname. */
			#pragma unroll
			for (int k = 0; k < MAX_LABELS; k++)
				hashes[k] = FNV1A_OFFSET;

			#pragma unroll
			for (int j = 0; j < MAX_QNAME; j++) {
				if ((__u32)j >= (__u32)nlen)
					break;
				__u8 c = q[j];
				if (c >= 'A' && c <= 'Z')
					c += 32;
				out[written++] = (char)c;

				if (just_saw_dot) {
					if (n_hashes < MAX_LABELS) {
						hashes[n_hashes] = FNV1A_OFFSET;
						n_hashes++;
					}
					just_saw_dot = 0;
				}

				/* Same unconditional 4-slot update as parse_qname. */
				hashes[0] = (hashes[0] ^ c) * FNV1A_PRIME;
				hashes[1] = (hashes[1] ^ c) * FNV1A_PRIME;
				hashes[2] = (hashes[2] ^ c) * FNV1A_PRIME;
				hashes[3] = (hashes[3] ^ c) * FNV1A_PRIME;

				if (c == '.')
					just_saw_dot = 1;
			}
			*n_hashes_out = n_hashes;
			return (int)written;
		}
		p += elen;
	}
	return -1;
}

#endif /* __ADBLOCKER_PARSERS_H__ */
