// Package cli wires every subcommand of `adblockerctl` together.
// Subcommands live in their own files for readability:
//
//	daemon     -> daemon.go
//	block      -> mutate.go
//	unblock    -> mutate.go
//	temp-block -> mutate.go
//	allow      -> mutate.go
//	list       -> list.go
//	stats      -> stats.go
//	update     -> update.go
package cli

import (
	"github.com/ebpf-adblocker/ebpf-adblocker/internal/version"
	"github.com/spf13/cobra"
)

// NewRoot builds the top-level cobra command with every subcommand
// already attached. The binary's main() just calls Execute().
func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "adblockerctl",
		Short:         "system-wide eBPF ad/tracker blocker",
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	// Use a multi-line --version output so users can paste it into bug reports.
	root.SetVersionTemplate(`{{.Use}} {{.Version}}
`)

	root.AddCommand(
		newDaemonCmd(),
		newBlockCmd(),
		newUnblockCmd(),
		newTempBlockCmd(),
		newAllowCmd(),
		newListCmd(),
		newStatsCmd(),
		newUpdateCmd(),
	)
	return root
}
