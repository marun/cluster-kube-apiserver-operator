package gracefulmonitor

import (
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

// NewInsecureReadyzCommand creates a insecure-readyz command.
func NewGracefulMonitorCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "graceful-monitor",
		Short: "Monitor static pod rollout to transition between revisions gracefully",
		Run: func(cmd *cobra.Command, args []string) {
			if err := run(); err != nil {
				klog.Fatal(err)
			}
		},
	}
}

func run() error {
	return nil
}
