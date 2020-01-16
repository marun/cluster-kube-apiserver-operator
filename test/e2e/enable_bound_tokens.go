package e2e

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	tokenctl "github.com/openshift/cluster-kube-apiserver-operator/pkg/operator/boundsatokensignercontroller"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/operator/operatorclient"
)

// Add the following and comment out the operator initialization in
// the starter.
//
// ctx := context.Background()
// err = startTokenController(ctx, kubeConfig)
// defer func() {
// 	ctx.Done()
// }()
func startTokenController(ctx context.Context, config *rest.Config) error {
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	kubeInformersForNamespaces := v1helpers.NewKubeInformersForNamespaces(
		kubeClient,
		"",
		operatorclient.GlobalMachineSpecifiedConfigNamespace,
		operatorclient.TargetNamespace,
		operatorclient.OperatorNamespace,
	)
	namespaceRef := &corev1.ObjectReference{
		Namespace: operatorclient.OperatorNamespace,
	}
	eventRecorder := events.NewKubeRecorder(
		kubeClient.CoreV1().Events(namespaceRef.Namespace),
		"test-bound-token-controller",
		namespaceRef,
	)
	controller := tokenctl.NewBoundSATokenSignerController(
		kubeInformersForNamespaces,
		kubeClient,
		eventRecorder,
	)

	kubeInformersForNamespaces.Start(ctx.Done())
	go controller.Run(ctx.Done())

	return nil
}
