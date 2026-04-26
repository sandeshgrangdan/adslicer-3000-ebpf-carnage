package loader

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// PinDir is where every map and (when applicable) link gets pinned.
// All four maps live under this directory.
const PinDir = "/sys/fs/bpf/adblocker"

// Stat slot indices - keep in lockstep with bpf/maps.h.
const (
	StatPktsSeen = iota
	StatDNSParsed
	StatSNIParsed
	StatBlockedDNS
	StatBlockedSNI
	StatBlockedIP
	StatPassed
	StatMax
)

// Domain entry flags - in lockstep with bpf/maps.h.
const (
	FlagBlock uint8 = 1
	FlagAllow uint8 = 2
	FlagTemp  uint8 = 4
)

// DomainEntry mirrors `struct domain_entry` in bpf/maps.h. Field
// layout, padding, and endianness must stay byte-for-byte identical.
type DomainEntry struct {
	Flags     uint8
	_         [7]uint8 // pad to 8B alignment so ExpiresAt sits on a u64 boundary
	ExpiresAt uint64   // unix nanoseconds; 0 = never
}

// BlockEvent mirrors `struct block_event` in bpf/maps.h.
type BlockEvent struct {
	TsNs       uint64
	DomainHash uint64
	Saddr      uint32
	Daddr      uint32
	Sport      uint16
	Dport      uint16
	Reason     uint8
	_          [7]uint8
	Qname      [128]byte
}

// IPv4LPMKey mirrors `struct ipv4_lpm_key`.
type IPv4LPMKey struct {
	PrefixLen uint32
	Addr      uint32 // network byte order to match the kernel
}

// Reason values for BlockEvent.Reason.
const (
	ReasonDNS uint8 = 1
	ReasonSNI uint8 = 2
	ReasonIP  uint8 = 3
)

// Loader owns every kernel-side resource we open: maps, programs, and
// attached links. Close() must be called for clean detach.
type Loader struct {
	objs   adblockerObjects
	tcLnks []link.Link
	xdLnks []link.Link
}

// New loads, pins, and attaches the BPF programs to the given
// interfaces. If `ifaces` is empty we auto-detect every non-loopback
// interface that's currently up.
func New(ifaces []string) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	if err := os.MkdirAll(PinDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir pin dir %s: %w", PinDir, err)
	}

	l := &Loader{}
	opts := ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: PinDir}}
	if err := loadAdblockerObjects(&l.objs, &opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier rejected program:\n%+v", ve)
		}
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	if len(ifaces) == 0 {
		auto, err := autoDetectIfaces()
		if err != nil {
			l.Close()
			return nil, err
		}
		ifaces = auto
	}
	if len(ifaces) == 0 {
		l.Close()
		return nil, errors.New("no usable interfaces (no non-loopback up interfaces found)")
	}

	for _, name := range ifaces {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", name, err)
			continue
		}
		// TC egress is the primary hook.
		tc, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   l.objs.TcEgress,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("attach tc egress on %s: %w", name, err)
		}
		l.tcLnks = append(l.tcLnks, tc)

		// XDP ingress is best-effort; skip silently if iface refuses.
		xd, err := link.AttachXDP(link.XDPOptions{
			Interface: iface.Index,
			Program:   l.objs.XdpIngress,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "xdp attach skipped on %s: %v\n", name, err)
			continue
		}
		l.xdLnks = append(l.xdLnks, xd)
	}
	return l, nil
}

// AttachExisting opens the four pinned maps without loading or
// attaching any programs. CLI subcommands like `block` and `unblock`
// use it to manipulate state in a running daemon.
func AttachExisting() (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}
	l := &Loader{}
	open := func(name string, m **ebpf.Map) error {
		x, err := ebpf.LoadPinnedMap(filepath.Join(PinDir, name), nil)
		if err != nil {
			return fmt.Errorf("open pinned map %s: %w (is the daemon running?)", name, err)
		}
		*m = x
		return nil
	}
	if err := open("blocklist", &l.objs.Blocklist); err != nil {
		return nil, err
	}
	if err := open("ip_blocklist", &l.objs.IpBlocklist); err != nil {
		l.Close()
		return nil, err
	}
	if err := open("stats", &l.objs.Stats); err != nil {
		l.Close()
		return nil, err
	}
	if err := open("events", &l.objs.Events); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Close detaches every link and closes every map / program file
// descriptor. Pins on disk are left in place so AttachExisting still
// works after the daemon restarts.
func (l *Loader) Close() error {
	for _, k := range l.tcLnks {
		_ = k.Close()
	}
	for _, k := range l.xdLnks {
		_ = k.Close()
	}
	return l.objs.Close()
}

// Blocklist returns the domain hash map.
func (l *Loader) Blocklist() *ebpf.Map { return l.objs.Blocklist }

// IPBlocklist returns the LPM trie.
func (l *Loader) IPBlocklist() *ebpf.Map { return l.objs.IpBlocklist }

// Stats returns the per-CPU stats array.
func (l *Loader) Stats() *ebpf.Map { return l.objs.Stats }

// Events returns the ring buffer reader. Caller must Close it.
func (l *Loader) Events() (*ringbuf.Reader, error) {
	return ringbuf.NewReader(l.objs.Events)
}

// IPv4Key builds an LPM key from a /N CIDR. Stored in network byte
// order to match the kernel.
func IPv4Key(ip net.IP, prefix uint32) IPv4LPMKey {
	v4 := ip.To4()
	if v4 == nil {
		return IPv4LPMKey{}
	}
	return IPv4LPMKey{PrefixLen: prefix, Addr: binary.BigEndian.Uint32(v4)}
}

func autoDetectIfaces() ([]string, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	var out []string
	for _, i := range all {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		out = append(out, i.Name)
	}
	return out, nil
}
