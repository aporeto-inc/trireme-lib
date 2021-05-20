package k8smonitor

import (
	"context"
	"sync"
	"time"

	"github.com/golang/mock/gomock"

	"go.aporeto.io/enforcerd/internal/extractors/containermetadata"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/config"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/external"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/external/mockexternal"
	"go.aporeto.io/enforcerd/trireme-lib/policy/mockpolicy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cri/mockcri"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

type unitTestMonitorMocks struct {
	podCache            *MockpodCacheInterface
	runtimeCache        *MockruntimeCacheInterface
	policy              *mockpolicy.MockResolver
	externalEventSender *mockexternal.MockReceiverRegistration
	cri                 *mockcri.MockExtendedRuntimeService
}

func newUnitTestMonitor(ctrl *gomock.Controller) (*K8sMonitor, *unitTestMonitorMocks) {
	podCache := NewMockpodCacheInterface(ctrl)
	runtimeCache := NewMockruntimeCacheInterface(ctrl)
	policyResolver := mockpolicy.NewMockResolver(ctrl)
	externalEventSender := mockexternal.NewMockReceiverRegistration(ctrl)
	cri := mockcri.NewMockExtendedRuntimeService(ctrl)

	mocks := &unitTestMonitorMocks{
		podCache:            podCache,
		runtimeCache:        runtimeCache,
		policy:              policyResolver,
		externalEventSender: externalEventSender,
		cri:                 cri,
	}

	return &K8sMonitor{
		nodename:        "test",
		startEventRetry: func(containermetadata.CommonKubernetesContainerMetadata, uint) {},
		podCache:        podCache,
		runtimeCache:    runtimeCache,
		handlers: &config.ProcessorConfig{
			Policy:              policyResolver,
			ExternalEventSender: []external.ReceiverRegistration{externalEventSender},
			ResyncLock:          &sync.RWMutex{},
		},
		criRuntimeService:                cri,
		cniInstalledOrRuncProxyStartedCh: make(chan struct{}),
	}, mocks
}

func setupInformerForUnitTests(ctx context.Context, kubeClient kubernetes.Interface, nodeName string) listersv1.PodLister {
	// get the pod informer from the default factory
	// add a field selector to narrow down our results
	fieldSelector := fields.OneTermEqualSelector(nodeNameKeyIndex, nodeName).String()
	factory := informers.NewSharedInformerFactoryWithOptions(kubeClient, time.Hour*24, informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
		opts.FieldSelector = fieldSelector
	}))
	informer := factory.Core().V1().Pods().Informer()

	// add an indexer so that our field selector by node name will work
	informer.AddIndexers(cache.Indexers{ // nolint: errcheck
		nodeNameKeyIndex: func(obj interface{}) ([]string, error) {
			// this is essentially exactly what the node lifecycel controller uses as well
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return []string{}, nil
			}
			if len(pod.Spec.NodeName) == 0 {
				return []string{}, nil
			}
			return []string{pod.Spec.NodeName}, nil
		},
	})

	// now start the informer
	go informer.Run(ctx.Done())

	// wait for the caches to sync before we return
	// if this fails, we can print a log, but this is not a
	if !cache.WaitForNamedCacheSync("pods", ctx.Done(), informer.HasSynced) {
		panic("K8sMonitor: setupInformer: waiting for caches timed out")
	}

	// return with a lister of the cache of this informer
	return listersv1.NewPodLister(informer.GetIndexer())
}
