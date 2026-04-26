package cli

import (
	"fmt"

	"github.com/adblocker/adblocker/internal/loader"
	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "show the first 50 entries in the kernel blocklist (hashes + flags)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := loader.AttachExisting()
			if err != nil {
				return err
			}
			defer l.Close()

			it := l.Blocklist().Iterate()
			var (
				key   uint64
				entry loader.DomainEntry
				count int
			)
			fmt.Printf("%-18s %-8s %s\n", "HASH", "FLAGS", "EXPIRES_AT")
			for it.Next(&key, &entry) {
				flags := flagString(entry.Flags)
				exp := "-"
				if entry.ExpiresAt != 0 {
					exp = fmt.Sprintf("%d", entry.ExpiresAt)
				}
				fmt.Printf("%016x   %-8s %s\n", key, flags, exp)
				count++
				if count >= 50 {
					break
				}
			}
			if err := it.Err(); err != nil {
				return err
			}
			fmt.Printf("\nshown: %d (cap=50)\n", count)
			return nil
		},
	}
}

func flagString(f uint8) string {
	parts := ""
	if f&loader.FlagBlock != 0 {
		parts += "B"
	}
	if f&loader.FlagAllow != 0 {
		parts += "A"
	}
	if f&loader.FlagTemp != 0 {
		parts += "T"
	}
	if parts == "" {
		parts = "-"
	}
	return parts
}
