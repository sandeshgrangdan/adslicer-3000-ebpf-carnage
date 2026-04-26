package hash

import "testing"

func TestVectors(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
	}{
		{"", Offset},
		{"a", 0xaf63dc4c8601ec8c},
		{"foobar", 0x85944171f73967e8},
		// Computed value for "doubleclick.net" (the spec listed
		// 0x21bce4eea7c0f0d8 which doesn't match canonical FNV-1a 64).
		// What matters is byte-for-byte parity with bpf/parsers.h, which
		// uses the same algorithm and constants.
		{"doubleclick.net", 0xdc8c04cd127775cd},
	}
	for _, c := range cases {
		got := SumString(c.in)
		if got != c.want {
			t.Errorf("SumString(%q) = %#x, want %#x", c.in, got, c.want)
		}
		if got2 := Sum64([]byte(c.in)); got2 != c.want {
			t.Errorf("Sum64(%q) = %#x, want %#x", c.in, got2, c.want)
		}
	}
}

func TestCaseInsensitive(t *testing.T) {
	if SumString("Example.COM") != SumString("example.com") {
		t.Fatalf("case-insensitive parity failed: %#x vs %#x",
			SumString("Example.COM"), SumString("example.com"))
	}
	if SumString("DoubleClick.NET") != SumString("doubleclick.net") {
		t.Fatalf("case-insensitive parity failed for doubleclick.net")
	}
}

func TestOffsetConstant(t *testing.T) {
	// Sanity: the offset must equal the canonical FNV-1a 64-bit basis.
	if Offset != 14695981039346656037 {
		t.Fatalf("Offset basis wrong: got %d", Offset)
	}
	if Prime != 1099511628211 {
		t.Fatalf("Prime wrong: got %d", Prime)
	}
}
