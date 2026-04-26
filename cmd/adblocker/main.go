// adblockerctl is the system-wide eBPF ad/tracker blocker. See README.md
// for architecture notes; everything interesting lives in internal/cli.
package main

import (
	"fmt"
	"os"

	"github.com/ebpf-adblocker/ebpf-adblocker/internal/cli"
)

func main() {
	if err := cli.NewRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
