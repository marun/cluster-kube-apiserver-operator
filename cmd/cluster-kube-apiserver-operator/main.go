package main

import (
	"context"
	goflag "flag"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	corev1 "k8s.io/api/core/v1"
	utilflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/logs"

	"github.com/openshift/cluster-kube-apiserver-operator/pkg/cmd/certregenerationcontroller"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/cmd/checkendpoints"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/cmd/gracefulmonitor"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/cmd/insecurereadyz"
	operatorcmd "github.com/openshift/cluster-kube-apiserver-operator/pkg/cmd/operator"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/cmd/render"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/cmd/resourcegraph"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/operator"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/version"
	"github.com/openshift/library-go/pkg/operator/staticpod/certsyncpod"
	"github.com/openshift/library-go/pkg/operator/staticpod/installerpod"
	"github.com/openshift/library-go/pkg/operator/staticpod/prune"
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	pflag.CommandLine.SetNormalizeFunc(utilflag.WordSepNormalizeFunc)
	pflag.CommandLine.AddGoFlagSet(goflag.CommandLine)

	logs.InitLogs()
	defer logs.FlushLogs()

	command := NewOperatorCommand(context.Background())
	if err := command.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func NewOperatorCommand(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster-kube-apiserver-operator",
		Short: "OpenShift cluster kube-apiserver operator",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
			os.Exit(1)
		},
	}

	if v := version.Get().String(); len(v) == 0 {
		cmd.Version = "<unknown>"
	} else {
		cmd.Version = v
	}

	cmd.AddCommand(operatorcmd.NewOperator())
	cmd.AddCommand(render.NewRenderCommand())
	cmd.AddCommand(NewInstallerCommand())
	cmd.AddCommand(prune.NewPrune())
	cmd.AddCommand(resourcegraph.NewResourceChainCommand())
	cmd.AddCommand(certsyncpod.NewCertSyncControllerCommand(operator.CertConfigMaps, operator.CertSecrets))
	cmd.AddCommand(certregenerationcontroller.NewCertRegenerationControllerCommand(ctx))
	cmd.AddCommand(insecurereadyz.NewInsecureReadyzCommand())
	cmd.AddCommand(checkendpoints.NewCheckEndpointsCommand())
	cmd.AddCommand(gracefulmonitor.NewGracefulMonitorCommand())

	return cmd
}

func NewInstallerCommand() *cobra.Command {
	installerOptions := installerpod.NewInstallOptions().
		WithInitializeFn(func(o *installerpod.InstallOptions) error {
			// TODO(marun) Only configure graceful for single replica topology

			manifests, err := gracefulmonitor.ReadStaticPodManifests(o.PodManifestDir, "kube-apiserver-pod-", "kube-apiserver")
			if err != nil {
				return err
			}

			activeManifest := manifests.ActiveManifest()

			// Prune all but the active manifest
			for _, manifest := range manifests {
				if manifest.Filename == activeManifest.Filename {
					continue
				}
				if err := os.Remove(manifest.Filename); err != nil {
					return err
				}
			}

			// Determine the port map to use for substituting
			// configmap content (including the pod yaml).
			activePort := 0
			if activeManifest != nil {
				activePort = activeManifest.Port
			}
			portMap := gracefulmonitor.NextPortMap(activePort)

			o.WithPodMutationFn(func(pod *corev1.Pod) error {
				// Ensure the pod includes its revision so that a
				// node's pod's are differentiated in the API.
				revision := pod.Labels["revision"]
				revSuffix := fmt.Sprintf("-%s", revision)
				pod.Name = pod.Name + revSuffix
				return nil
			})
			o.WithSubstituteConfigMapContentFn(func(input string) string {
				// TODO(marun) Ensure uniquely-named logs are rotated/culled
				result := strings.ReplaceAll(
					input,
					"/var/log/kube-apiserver/audit.log",
					fmt.Sprintf("/var/log/kube-apiserver/audit-%s.log", o.Revision),
				)
				result = strings.ReplaceAll(
					result,
					"/var/log/kube-apiserver/.terminating",
					fmt.Sprintf("/var/log/kube-apiserver/.terminating-%s", o.Revision),
				)
				result = strings.ReplaceAll(
					result,
					"/var/log/kube-apiserver/termination.log",
					fmt.Sprintf("/var/log/kube-apiserver/termination-%s.log", o.Revision),
				)
				for port, substitutePort := range portMap {
					result = strings.ReplaceAll(result, fmt.Sprintf("%d", port), fmt.Sprintf("%d", substitutePort))
				}
				return result
			})
			o.WithCopyContentFn(func() error {
				// TODO(marun) Add support for copying the static
				return nil
			})

			return nil
		})
	return installerpod.NewInstallerWithOptions(installerOptions)
}

// // TODO(marun) Only modify the pod if graceful rollout is enabled (for SNO)
// func enableGraceful(pod *corev1.Pod) error {
// 	revision := pod.Labels["revision"]
// 	revSuffix := fmt.Sprintf("-%s", revision)

// 	pod.Name = pod.Name + revSuffix

// 	return nil

// TODO(marun) Is this complexity worth figuring out?
// securePort := int32(6443)
// insecurePort := int32(6080)
// checkEndpointsPort := int32(17697)

// securePortOverride := securePort + 1
// insecurePortOverride := insecurePort + 1
// checkEndpointsPortOverride := checkEndpointsPort + 1

// commonVars := map[string]string{
// 	"INSECURE_PORT": fmt.Sprintf("%s", insecurePortOverride),
// 	"SECURE_PORT":   fmt.Sprintf("%s", securePortOverride),
// 	// TODO(marun) Only supply this to setup and kube-apiserver containers
// 	"REV_SUFFIX": revSuffix,
// }

// for _, container := range pod.Spec.InitContainers {
// 	switch container.Name {
// 	case "setup":
// 		container.Env = applyToEnvVars(container.Env, commonVars)
// 		break
// 	default:
// 		klog.V(7).Infof("init container not modified for graceful rollout: %s",
// 			container.Name)
// 	}
// }

// for _, container := range pod.Spec.Containers {
// 	switch container.Name {
// 	case "kube-apiserver":
// 		container.Env = applyToEnvVars(container.Env, commonVars)
// 		err := overridePort(&container, securePort, securePortOverride)
// 		if err != nil {
// 			return err
// 		}
// 		container.LivenessProbe.HTTPGet.Port = intstr.FromInt(int(securePortOverride))
// 		container.ReadinessProbe.HTTPGet.Port = intstr.FromInt(int(securePortOverride))
// 	case "kube-apiserver-insecure-readyz":
// 		container.Env = applyToEnvVars(container.Env, commonVars)
// 		err := overridePort(&container, insecurePort, insecurePortOverride)
// 		if err != nil {
// 			return err
// 		}
// 	case "kube-apiserver-check-endpoints":
// 		container.Env = applyToEnvVars(container.Env, map[string]string{
// 			"CHECK_ENDPOINTS_PORT": fmt.Sprintf("%s", checkEndpointsPortOverride),
// 		})
// 		err := overridePort(&container, checkEndpointsPort, checkEndpointsPortOverride)
// 		if err != nil {
// 			return err
// 		}
// 		container.LivenessProbe.HTTPGet.Port = intstr.FromInt(int(checkEndpointsPortOverride))
// 		container.ReadinessProbe.HTTPGet.Port = intstr.FromInt(int(checkEndpointsPortOverride))
// 	default:
// 		klog.V(7).Infof("container not modified for graceful rollout: %s",
// 			container.Name)
// 	}
// }
// return nil
// }

// // applyToEnvVars returns a slice of env vars based on a provided slice with the
// // map of values applied to it.
// func applyToEnvVars(envVars []corev1.EnvVar, newVars map[string]string) []corev1.EnvVar {
// 	for key, value := range newVars {
// 		found := false
// 		for _, envVar := range envVars {
// 			if envVar.Name == key {
// 				envVar.Value = value
// 				found = true
// 			}
// 		}
// 		if !found {
// 			envVars = append(envVars, corev1.EnvVar{
// 				Name:  key,
// 				Value: value,
// 			})
// 		}
// 	}
// 	return envVars
// }

// // overridePort sets the value of the provided port with its override. An error
// // will be returned if the provided port is not present.
// func overridePort(container *corev1.Container, port, portOverride int32) error {
// 	overriden := false
// 	for _, containerPort := range container.Ports {
// 		if containerPort.ContainerPort == port {
// 			containerPort.ContainerPort = portOverride
// 			overriden = true
// 			break
// 		}
// 	}
// 	if !overriden {
// 		return fmt.Errorf("Unable to override missing port %d on container %s",
// 			port, container)

// 	}
// 	return nil
// }
