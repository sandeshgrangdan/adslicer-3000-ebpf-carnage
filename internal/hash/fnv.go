// Package hash implements FNV-1a 64-bit, byte-identical with the
// kernel-side implementation in bpf/parsers.h. If the two ever diverge,
// the kernel will compute one hash and user-space will look up another,
// silently breaking blocking. The test suite enforces parity.
package hash

const (
	// Offset is the 64-bit FNV-1a offset basis.
	Offset uint64 = 14695981039346656037
	// Prime is the 64-bit FNV-1a prime.
	Prime uint64 = 1099511628211
)

// Sum64 hashes b case-insensitively (lowercased ASCII) using FNV-1a.
// No NUL terminator is appended; the kernel iterates the same raw bytes.
func Sum64(b []byte) uint64 {
	h := Offset
	for _, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		h ^= uint64(c)
		h *= Prime
	}
	return h
}

// SumString is a convenience wrapper for string inputs.
func SumString(s string) uint64 {
	h := Offset
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		h ^= uint64(c)
		h *= Prime
	}
	return h
}
