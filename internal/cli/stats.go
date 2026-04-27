package cli

import (
	"fmt"

	"github.com/adblocker/adblocker/internal/loader"
	"github.com/spf13/cobra"
)

var statNames = [...]string{
	"PKTS_SEEN",
	"DNS_PARSED",
	"SNI_PARSED",
	"BLOCKED_DNS",
	"BLOCKED_SNI",
	"BLOCKED_IP",
	"PASSED",
}

func newStatsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "print summed per-CPU counters",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := loader.AttachExisting()
			if err != nil {
				return err
			}
			defer l.Close()

			fmt.Printf("%-14s %s\n", "COUNTER", "VALUE")
			for slot, name := range statNames {
				k := uint32(slot) //nolint:gosec // bounded by len(statNames)
				var perCPU []uint64
				if err := l.Stats().Lookup(&k, &perCPU); err != nil {
					fmt.Printf("%-14s ERR %v\n", name, err)
					continue
				}
				var sum uint64
				for _, v := range perCPU {
					sum += v
				}
				fmt.Printf("%-14s %d\n", name, sum)
			}
			return nil
		},
	}
}
