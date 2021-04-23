package k8smonitor

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"go.uber.org/zap"
)

var (
	errCacheUninitialized = errors.New("cache uninitialized")
	errSandboxEmpty       = errors.New("sandboxID must not be empty")
	errPodNil             = errors.New("pod must not be nil")
	errRuntimeNil         = errors.New("runtime must not be nil")
	errPodNameEmpty       = errors.New("pod name must not be empty")
	errPodNamespaceEmpty  = errors.New("nod namespace must not be empty")
	errSandboxNotFound    = errors.New("sandbox not found")
)

const (
	nodeNameKeyIndex = "spec.nodeName"
)

// needsUpdateFunc is a function which compares two pod objects and determines
// if we need to send an update event to the policy engine.
type needsUpdateFunc func(*corev1.Pod, *corev1.Pod) bool

// defaultNeedsUpdate simply compares if the labels changed.
// As we are using the reduced metadata extractor by now, this is
// the only change that we need to watch out for at the moment.
func defaultNeedsUpdate(prev, obj *corev1.Pod) bool {
	return !reflect.DeepEqual(prev.GetLabels(), obj.GetLabels())
}

type podCacheInterface interface {
	Delete(sandboxID string)
	Get(sandboxID string) *corev1.Pod
	Set(sandboxID string, pod *corev1.Pod) error
	FindSandboxID(name, namespace string) (string, error)
	SetupInformer(ctx context.Context, kubeClient kubernetes.Interface, nodeName string, needsUpdate needsUpdateFunc) listersv1.PodLister
}

var _ podCacheInterface = &podCache{}

type podCache struct {
	pods map[string]*corev1.Pod
	sync.RWMutex
	updateEvent updateEventFunc
}

func newPodCache(updateEvent updateEventFunc) *podCache {

	c := &podCache{
		pods:        make(map[string]*corev1.Pod),
		updateEvent: updateEvent,
	}
	return c
}

func (c *podCache) SetupInformer(ctx context.Context, kubeClient kubernetes.Interface, nodeName string, needsUpdate needsUpdateFunc) listersv1.PodLister {
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
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		// we only subscribe to pod update events
		UpdateFunc: func(prev, obj interface{}) {
			prevPod, ok := prev.(*corev1.Pod)
			if !ok {
				return
			}
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}

			if pod.Spec.NodeName != nodeName {
				// TODO: unit tests are hitting this
				// the added indexer and the FieldSelector which are added to the lister through the factory options
				// should prevent this code path from ever being hit.
				// This might be a shortcoming of the fake clientset. We have run into limitations before.
				zap.L().Debug("K8sMonitor: informer: received pod update event which does not belong to this node", zap.String("podNodeName", pod.Spec.NodeName), zap.String("nodeName", nodeName))
				return
			}

			if pod.Spec.HostNetwork {
				zap.L().Debug("K8sMonitor: informer: skipping host network pods", zap.String("podName", pod.GetName()),
					zap.String("podNamespace", pod.GetNamespace()),
					zap.String("nodeName", pod.Spec.NodeName))
				return
			}

			updateInternal := func(p *corev1.Pod) (string, error) {
				// find the sandbox for this pod
				sandboxID, err := c.FindSandboxID(p.GetName(), p.GetNamespace())
				if err != nil {
					// this can only happen if we were wrongly monitoring a pod which we shouldn't have
					// it's not the end of the world, but something might be up, let's log a debug message
					// The problem with this log message is: when a pod first starts up, it is bound to receive
					// update events. However, the kubelet has not started the pod yet, so we are not interested
					// in the event yet. There is unfortunately no way for us to distinguish between the two
					zap.L().Debug(
						"K8sMonitor: informer: sandbox for pod not found in cache. Will not update the processing unit",
						zap.String("podName", p.GetName()),
						zap.String("podNamespace", p.GetNamespace()),
						zap.String("nodeName", p.Spec.NodeName),
					)
					return "", err
				}
				// update it in our internal state
				if err := c.Set(sandboxID, p.DeepCopy()); err != nil {
					zap.L().Error(
						"K8sMonitor: informer: failed to update pod in cache",
						zap.String("sandboxID", sandboxID),
						zap.String("podName", p.GetName()),
						zap.String("podNamespace", p.GetNamespace()),
						zap.String("nodeName", p.Spec.NodeName),
					)
					return "", err
				}
				return sandboxID, nil
			}

			// now send the event to the policy engine if
			// 1. there is a update on the pod labels.
			if needsUpdate(prevPod, pod) {
				go func(ctx context.Context, p *corev1.Pod) {
					sandboxID, err := updateInternal(p)
					if err != nil {
						return
					}
					// now send the update event
					if err := c.updateEvent(ctx, sandboxID); err != nil {
						zap.L().Error(
							"K8sMonitor: informer: failed to send update event to policy engine",
							zap.String("sandboxID", sandboxID),
							zap.Error(err),
						)
					}
				}(ctx, pod)
			} else {
				zap.L().Debug(
					"K8sMonitor: informer: no update event necessary",
					zap.String("podName", pod.GetName()),
					zap.String("podNamespace", pod.GetNamespace()),
				)

				// try to update the internal state anyway
				// this is technically not required at the moment
				// but we never know when it might
				go updateInternal(pod) // nolint
			}
		},
	})

	// now start the informer
	go informer.Run(ctx.Done())

	// wait for the caches to sync before we return
	// if this fails, we can print a log, but this is not a
	if !cache.WaitForNamedCacheSync("pods", ctx.Done(), informer.HasSynced) {
		zap.L().Warn("K8sMonitor: setupInformer: waiting for caches timed out")
	}

	// return with a lister of the cache of this informer
	return listersv1.NewPodLister(informer.GetIndexer())
}

func (c *podCache) Get(sandboxID string) *corev1.Pod {
	if c == nil {
		return nil
	}
	c.RLock()
	defer c.RUnlock()
	if c.pods == nil {
		return nil
	}
	p, ok := c.pods[sandboxID]
	if !ok {
		return nil
	}
	return p.DeepCopy()
}

// FindSandboxID returns the sandbox ID of the pod that matches name and namespace.
// It returns an error in all other cases - also if the sandbox is not in the cache.
func (c *podCache) FindSandboxID(name, namespace string) (string, error) {
	if c == nil {
		return "", errCacheUninitialized
	}
	if c.pods == nil {
		return "", errCacheUninitialized
	}
	if name == "" {
		return "", errPodNameEmpty
	}
	if namespace == "" {
		return "", errPodNamespaceEmpty
	}
	c.RLock()
	defer c.RUnlock()
	for sandboxID, pod := range c.pods {
		if pod.GetName() == name && pod.GetNamespace() == namespace {
			return sandboxID, nil
		}
	}
	return "", errSandboxNotFound
}

func (c *podCache) Set(sandboxID string, pod *corev1.Pod) error {
	if c == nil {
		return errCacheUninitialized
	}
	if sandboxID == "" {
		return errSandboxEmpty
	}
	if pod == nil {
		return errPodNil
	}
	c.Lock()
	defer c.Unlock()
	if c.pods == nil {
		return errCacheUninitialized
	}
	c.pods[sandboxID] = pod
	return nil
}

func (c *podCache) Delete(sandboxID string) {
	if c == nil {
		return
	}
	c.Lock()
	defer c.Unlock()
	delete(c.pods, sandboxID)
}
