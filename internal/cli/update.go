package cli

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"
)

func newUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "trigger a refresh of the upstream lists",
		Long: `Trigger a refresh of upstream blocklists.

The daemon listens for SIGHUP to reload, but for now the cleanest way
to force a refresh is to restart the systemd unit. This command runs
'systemctl restart adblocker' for you. If systemctl is unavailable
(developer machine, container) the command falls back to a no-op
message.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := exec.LookPath("systemctl"); err != nil {
				fmt.Println("systemctl not found - please send SIGHUP to the daemon manually.")
				return nil
			}
			c := exec.Command("systemctl", "restart", "adblocker")
			c.Stdout = cmd.OutOrStdout()
			c.Stderr = cmd.ErrOrStderr()
			if err := c.Run(); err != nil {
				return fmt.Errorf("systemctl restart adblocker: %w", err)
			}
			fmt.Println("daemon restarted")
			return nil
		},
	}
}
