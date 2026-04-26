// STUB - this file mirrors what `go generate` (bpf2go) will write, so
// the loader package compiles before the kernel object has been built.
// `make generate` overwrites this file with the real version, including
// the embedded ELF and proper LoadCollectionSpec wiring. Until then,
// loadAdblockerObjects returns an error and no programs can attach.
//
// Build constraint matches what bpf2go emits for the little-endian
// target so the file is overwritten cleanly on `make generate`.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package loader

import (
	"errors"
	"io"

	"github.com/cilium/ebpf"
)

var errBPFNotGenerated = errors.New(
	"BPF object not generated yet - run `make generate` to invoke bpf2go " +
		"(needs clang + bpftool installed and bpf/vmlinux.h regenerated)")

func loadAdblocker() (*ebpf.CollectionSpec, error)        { return nil, errBPFNotGenerated }
func loadAdblockerObjects(_ interface{}, _ *ebpf.CollectionOptions) error {
	return errBPFNotGenerated
}

type adblockerSpecs struct {
	adblockerProgramSpecs
	adblockerMapSpecs
}

type adblockerProgramSpecs struct {
	TcEgress   *ebpf.ProgramSpec `ebpf:"tc_egress"`
	XdpIngress *ebpf.ProgramSpec `ebpf:"xdp_ingress"`
}

type adblockerMapSpecs struct {
	Blocklist   *ebpf.MapSpec `ebpf:"blocklist"`
	IpBlocklist *ebpf.MapSpec `ebpf:"ip_blocklist"`
	Stats       *ebpf.MapSpec `ebpf:"stats"`
	Events      *ebpf.MapSpec `ebpf:"events"`
}

type adblockerObjects struct {
	adblockerPrograms
	adblockerMaps
}

func (o *adblockerObjects) Close() error {
	return _AdblockerClose(&o.adblockerPrograms, &o.adblockerMaps)
}

type adblockerMaps struct {
	Blocklist   *ebpf.Map `ebpf:"blocklist"`
	IpBlocklist *ebpf.Map `ebpf:"ip_blocklist"`
	Stats       *ebpf.Map `ebpf:"stats"`
	Events      *ebpf.Map `ebpf:"events"`
}

func (m *adblockerMaps) Close() error {
	return _AdblockerClose(m.Blocklist, m.IpBlocklist, m.Stats, m.Events)
}

type adblockerPrograms struct {
	TcEgress   *ebpf.Program `ebpf:"tc_egress"`
	XdpIngress *ebpf.Program `ebpf:"xdp_ingress"`
}

func (p *adblockerPrograms) Close() error {
	return _AdblockerClose(p.TcEgress, p.XdpIngress)
}

func _AdblockerClose(closers ...io.Closer) error {
	for _, c := range closers {
		if c == nil {
			continue
		}
		if err := c.Close(); err != nil {
			return err
		}
	}
	return nil
}

// _AdblockerBytes is the embedded ELF after bpf2go runs. Empty in stub mode.
var _AdblockerBytes []byte
