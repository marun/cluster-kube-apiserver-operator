package boundsatokensignercontroller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"k8s.io/klog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/client-go/util/workqueue"

	"github.com/openshift/cluster-kube-apiserver-operator/pkg/operator/operatorclient"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	workQueueKey = "key"

	operatorNamespace = operatorclient.OperatorNamespace
	targetNamespace   = operatorclient.TargetNamespace

	keySize                  = 2048
	NextPrivateKeySecretName = "next-bound-service-account-private-key"
	PrivateKeySecretName     = "bound-service-account-private-key"
	PrivateKeyKey            = "bound-service-account.key"
	PublicKeyKey             = "bound-service-account.pub"

	TokenReadyAnnotation = "kube-apiserver.openshift.io/ready-to-use"
	readyInterval        = 5 * time.Minute

	CertConfigMapName = "bound-sa-token-signing-certs"
)

// BoundSATokenSignerController manages the keypair used to sign bound
// tokens and the key bundle used to verify them.
//
// This code is derived from the controller used by the
// kube-controller-manager-operator to manage the key material for the
// legacy sa token signer.
type BoundSATokenSignerController struct {
	secretClient    corev1client.SecretsGetter
	configMapClient corev1client.ConfigMapsGetter
	eventRecorder   events.Recorder

	cachesSynced []cache.InformerSynced

	// queue only ever has one item, but it has nice error handling backoff/retry semantics
	queue workqueue.RateLimitingInterface
}

func NewBoundSATokenSignerController(
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	kubeClient kubernetes.Interface,
	eventRecorder events.Recorder,

) *BoundSATokenSignerController {

	ret := &BoundSATokenSignerController{
		secretClient:    v1helpers.CachedSecretGetter(kubeClient.CoreV1(), kubeInformersForNamespaces),
		configMapClient: v1helpers.CachedConfigMapGetter(kubeClient.CoreV1(), kubeInformersForNamespaces),
		eventRecorder:   eventRecorder.WithComponentSuffix("bound-sa-token-signer-controller"),

		cachesSynced: []cache.InformerSynced{
			kubeInformersForNamespaces.InformersFor(operatorNamespace).Core().V1().Secrets().Informer().HasSynced,
			kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().Secrets().Informer().HasSynced,
			kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().ConfigMaps().Informer().HasSynced,
		},

		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "BoundSATokenSignerController"),
	}

	kubeInformersForNamespaces.InformersFor(operatorNamespace).Core().V1().Secrets().Informer().AddEventHandler(ret.eventHandler())
	kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().Secrets().Informer().AddEventHandler(ret.eventHandler())
	kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().ConfigMaps().Informer().AddEventHandler(ret.eventHandler())

	return ret
}

func (c *BoundSATokenSignerController) sync() error {
	signingSecret, err := c.secretClient.Secrets(operatorNamespace).Get(NextPrivateKeySecretName, metav1.GetOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	needKeypair := errors.IsNotFound(err) || len(signingSecret.Data[PrivateKeyKey]) == 0 || len(signingSecret.Data[PublicKeyKey]) == 0
	if needKeypair {
		newSecret, err := newSigningSecret()
		if err != nil {
			return err
		}
		signingSecret, _, err = resourceapply.ApplySecret(c.secretClient, c.eventRecorder, newSecret)
		if err != nil {
			return err
		}
		// requeue for after we should have recovered
		c.queue.AddAfter(workQueueKey, readyInterval+10*time.Second)
	}

	certConfigMap, err := c.configMapClient.ConfigMaps(targetNamespace).Get(CertConfigMapName, metav1.GetOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	if errors.IsNotFound(err) {
		certConfigMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: targetNamespace,
				Name:      CertConfigMapName,
			},
			Data: map[string]string{},
		}
	}
	currPublicKey := string(signingSecret.Data[PublicKeyKey])
	hasThisKey := false
	for _, value := range certConfigMap.Data {
		if value == currPublicKey {
			hasThisKey = true
			break
		}
	}
	if !hasThisKey {
		// Increment until a unique name is found
		nextKeyIndex := len(certConfigMap.Data) + 1
		nextKeyKey := ""
		for len(nextKeyKey) == 0 {
			possibleKey := fmt.Sprintf("bound-service-account-%03d.pub", nextKeyIndex)
			_, ok := certConfigMap.Data[possibleKey]
			if !ok {
				nextKeyKey = possibleKey
				break
			}
			nextKeyIndex += 1
		}

		certConfigMap.Data[nextKeyKey] = currPublicKey
		certConfigMap, _, err = resourceapply.ApplyConfigMap(c.configMapClient, c.eventRecorder, certConfigMap)
		if err != nil {
			return err
		}
	}

	// Check if next-bound-sa-private-key has been around long enough to be promoted.
	// Giving time for apiserver instances to pick up the change in public keys before
	// changing the private key minimizes the potential for one or more apiservers to
	// issue tokens signed by the new private key that apiservers without the
	// corresponding public key are unable to validate.
	//
	// TODO(marun) Find a more accurate indication that all apiservers are capable of
	// validating tokens signed by the new private key.
	readyToPromote := false
	readyTime := signingSecret.Annotations[TokenReadyAnnotation]
	if len(readyTime) == 0 {
		readyToPromote = true
	} else {
		promotionTime, err := time.Parse(time.RFC3339, readyTime)
		if err != nil || time.Now().After(promotionTime) {
			readyToPromote = true
		}
	}

	// If past promotion time, make the new private key available to the operand.
	if readyToPromote {
		_, _, err := resourceapply.SyncSecret(c.secretClient, c.eventRecorder,
			operatorNamespace, NextPrivateKeySecretName,
			targetNamespace, PrivateKeySecretName, []metav1.OwnerReference{})
		return err
	}

	return nil
}

func (c *BoundSATokenSignerController) Run(ctx context.Context) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting BoundSATokenSignerController")
	defer klog.Infof("Shutting down BoundSATokenSignerController")

	if !cache.WaitForCacheSync(ctx.Done(), c.cachesSynced...) {
		utilruntime.HandleError(fmt.Errorf("caches did not sync"))
		return
	}

	stopCh := ctx.Done()

	// Run only a single worker
	go wait.Until(c.runWorker, time.Second, stopCh)

	// start a time based thread to ensure we stay up to date
	go wait.Until(func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for {
			c.queue.Add(workQueueKey)
			select {
			case <-ticker.C:
			case <-stopCh:
				return
			}
		}

	}, time.Minute, stopCh)

	<-stopCh
}

func (c *BoundSATokenSignerController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *BoundSATokenSignerController) processNextWorkItem() bool {
	dsKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(dsKey)

	err := c.sync()
	if err == nil {
		c.queue.Forget(dsKey)
		return true
	}

	utilruntime.HandleError(err)
	c.queue.AddRateLimited(dsKey)

	return true
}

// eventHandler queues the operator to check spec and status
func (c *BoundSATokenSignerController) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.queue.Add(workQueueKey) },
		UpdateFunc: func(old, new interface{}) { c.queue.Add(workQueueKey) },
		DeleteFunc: func(obj interface{}) { c.queue.Add(workQueueKey) },
	}
}

// newSigningSecret creates a new secret populated with a new keypair.
func newSigningSecret() (*corev1.Secret, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, err
	}
	privateBytes, err := keyutil.MarshalPrivateKeyToPEM(rsaKey)
	if err != nil {
		return nil, err
	}
	publicBytes, err := publicKeyToPem(&rsaKey.PublicKey)
	if err != nil {
		return nil, err
	}
	readyTime := time.Now().Add(readyInterval).Format(time.RFC3339)
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: operatorNamespace,
			Name:      NextPrivateKeySecretName,
			Annotations: map[string]string{
				TokenReadyAnnotation: readyTime,
			},
		},
		Data: map[string][]byte{
			PrivateKeyKey: privateBytes,
			PublicKeyKey:  publicBytes,
		},
	}, nil
}

func publicKeyToPem(key *rsa.PublicKey) ([]byte, error) {
	keyInBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	keyinPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: keyInBytes,
		},
	)
	return keyinPem, nil
}
