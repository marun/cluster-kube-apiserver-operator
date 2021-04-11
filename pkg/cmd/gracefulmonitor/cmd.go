package gracefulmonitor

import (
	"fmt"
	"os"

	"github.com/coreos/go-iptables/iptables"
	"github.com/davecgh/go-spew/spew"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
)

type GracefulMonitorOptions struct {
	PodManifestDir string
}

func NewGracefulMonitorCommand() *cobra.Command {
	o := GracefulMonitorOptions{}

	cmd := &cobra.Command{
		Use:   "graceful-monitor",
		Short: "Monitors static pod state and ensures a graceful transition between old and new pods.",
		Run: func(cmd *cobra.Command, args []string) {
			klog.V(1).Info(cmd.Flags())
			klog.V(1).Info(spew.Sdump(o))

			if err := o.Validate(); err != nil {
				klog.Exit(err)
			}

			if err := o.Run(); err != nil {
				klog.Exit(err)
			}
		},
	}

	return cmd
}

func (o *GracefulMonitorOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.PodManifestDir, "pod-manifest-dir", "/etc/kubernetes/manifests", "directory for the static pod manifests")
}

func (o *GracefulMonitorOptions) Validate() error {
	if len(o.PodManifestDir) == 0 {
		return fmt.Errorf("--pod-manifest-dir is required")
	}

	return nil
}

func (o *GracefulMonitorOptions) Run() error {
	// TODO(marun) Watch for changes to apiserver static pod manifests
	// TODO(marun) Maintain rules even when manifests do not change

	return gracefulRollout(o.PodManifestDir)
}

func gracefulRollout(manifestDir string) error {
	podPrefix := "kube-apiserver-pod-"
	containerName := "kube-apiserver"

	manifests, err := ReadStaticPodManifests(manifestDir, podPrefix, containerName)
	if err != nil {
		return err
	}
	switch len(manifests) {
	case 0:
		// TODO(marun) Should the chain rules be flushed?
		klog.V(1).Infof("No static pod manifests found in path %q with prefix %q",
			manifestDir, podPrefix)
		return nil
	case 1:
		klog.V(1).Info("Ensuring port forwarding for revision %d on port %d",
			manifests[0].Revision, manifests[0].Port)
	case 2:
		klog.V(1).Info("Attempting graceful transition from revision %d on port %d and revision %d on port %d",
			manifests[0].Revision, manifests[0].Port, manifests[1].Revision, manifests[1].Port)
	default:
		klog.Warningf("Graceful transition only possible for 2 pods, but %d found.", len(manifests))
	}

	activeManifest := manifests.ActiveManifest()
	activeMap := activePortMap(activeManifest.Port)

	// TODO(marun) Ensure support for ipv6
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	// Ensure the active rules
	if err := ensureActiveRules(ipt, activeMap); err != nil {
		return err
	}
	if len(manifests) == 1 {
		// No pod to transition to
		return nil
	}

	// Wait for the next pod to become ready by health checking its
	// insecure port.
	nextMap := NextPortMap(activeManifest.Port)
	nextInsecurePort := nextMap[6080]
	if err := waitForConnRefused(nextInsecurePort); err != nil {
		return err
	}

	// New pod is ready

	// Ensure established and related connections continue to be
	// forwarded to the old pod and forward new connections to the new
	// pod.
	if err := ensureTransitionRules(ipt, activeMap, nextMap); err != nil {
		if err := ensureActiveRules(ipt, activeMap); err != nil {
			klog.Errorf("Error attempting to cleanup forwarding rules: %v", err)
			return err
		}
		return err
	}

	// Remove the old pod's manifest
	if err := os.Remove(activeManifest.Filename); err != nil {
		if err := ensureActiveRules(ipt, activeMap); err != nil {
			klog.Errorf("Error attempting to cleanup forwarding rules: %v", err)
			return err
		}
		return err
	}

	// Wait for the old pod to stop serving traffic
	activeInsecurePort := activeMap[6080]
	if err := waitForConnRefused(activeInsecurePort); err != nil {
		if err := ensureActiveRules(ipt, activeMap); err != nil {
			klog.Errorf("Error attempting to cleanup forwarding rules: %v", err)
			return err
		}
		return err
	}

	// Old pod is gone

	// Ensure all traffic is forwarded to the new pod
	return ensureActiveRules(ipt, nextMap)
}

func waitForConnRefused(port int) error {
	// TODO(marun) Implement healthcheck
	return nil
}

func activePortMap(activePort int) map[int]int {
	offset := activePort % 6443
	return portMapForOffset(offset)
}

func NextPortMap(activePort int) map[int]int {
	// Next active port is 6444
	offset := 1
	if activePort == 6444 {
		// Next active port is 6445
		offset = 2
	}
	return portMapForOffset(offset)
}

func portMapForOffset(offset int) map[int]int {
	securePort := 6443
	insecurePort := 6080
	checkPort := 17697
	return map[int]int{
		securePort:   securePort + offset,
		insecurePort: insecurePort + offset,
		checkPort:    checkPort + offset,
	}
}
