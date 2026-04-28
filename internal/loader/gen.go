// Package loader manages the BPF object lifecycle: load, attach, pin,
// detach. It also exposes typed helpers around the four pinned maps so
// the CLI and daemon don't need to know map keys/value layouts.
//
// The bpf2go directive lives in this dedicated file so the package
// always parses, even before `make generate` has produced the
// adblocker_bpfel.go bindings.
package loader

// -Wno-pass-failed silences clang's "loop not unrolled" warnings when
// the optimizer can't honor a `#pragma unroll` hint. The loops are
// still bounded with explicit `break`s; modern BPF verifiers handle
// bounded loops natively. Without -Wno-pass-failed, -Werror promotes
// these advisory warnings into hard build failures (clang 18+).
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -Werror -Wno-pass-failed -I../../bpf" adblocker ../../bpf/adblocker.bpf.c
