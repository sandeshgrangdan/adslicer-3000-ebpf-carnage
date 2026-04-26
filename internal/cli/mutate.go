package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/ebpf-adblocker/ebpf-adblocker/internal/hash"
	"github.com/ebpf-adblocker/ebpf-adblocker/internal/lists"
	"github.com/ebpf-adblocker/ebpf-adblocker/internal/loader"
	"github.com/spf13/cobra"
)

func newBlockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "block <domain>...",
		Short: "permanently block one or more domains",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return setEntries(args, loader.FlagBlock, 0)
		},
	}
}

func newUnblockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unblock <domain>...",
		Short: "remove one or more domains from the blocklist",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			l, err := loader.AttachExisting()
			if err != nil {
				return err
			}
			defer l.Close()
			for _, raw := range args {
				d := strings.ToLower(strings.TrimSpace(raw))
				if !lists.ValidDomain(d) {
					fmt.Printf("skip invalid: %s\n", raw)
					continue
				}
				h := hash.SumString(d)
				if err := l.Blocklist().Delete(&h); err != nil {
					fmt.Printf("delete %s: %v\n", d, err)
					continue
				}
				fmt.Printf("unblocked: %s\n", d)
			}
			return nil
		},
	}
}

func newTempBlockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "temp-block <domain> <duration>",
		Short: "block a domain temporarily (e.g. 2h, 30m, 24h)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			d := strings.ToLower(strings.TrimSpace(args[0]))
			if !lists.ValidDomain(d) {
				return fmt.Errorf("invalid domain: %s", args[0])
			}
			dur, err := time.ParseDuration(args[1])
			if err != nil {
				return fmt.Errorf("invalid duration %q: %w", args[1], err)
			}
			if dur <= 0 {
				return fmt.Errorf("duration must be positive")
			}
			expires := uint64(time.Now().Add(dur).UnixNano())
			return setEntries([]string{d}, loader.FlagBlock|loader.FlagTemp, expires)
		},
	}
}

func newAllowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "allow <domain>...",
		Short: "allow a domain (overrides upstream blocklists)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return setEntries(args, loader.FlagAllow, 0)
		},
	}
}

// setEntries inserts or updates one or more domain entries in the
// kernel `blocklist` map with the given flags and expiry.
func setEntries(args []string, flags uint8, expires uint64) error {
	l, err := loader.AttachExisting()
	if err != nil {
		return err
	}
	defer l.Close()

	for _, raw := range args {
		d := strings.ToLower(strings.TrimSpace(raw))
		if !lists.ValidDomain(d) {
			fmt.Printf("skip invalid: %s\n", raw)
			continue
		}
		h := hash.SumString(d)
		entry := loader.DomainEntry{Flags: flags, ExpiresAt: expires}
		if err := l.Blocklist().Update(&h, &entry, ebpf.UpdateAny); err != nil {
			fmt.Printf("update %s: %v\n", d, err)
			continue
		}
		fmt.Printf("set: %s flags=0x%x hash=%016x\n", d, flags, h)
	}
	return nil
}
