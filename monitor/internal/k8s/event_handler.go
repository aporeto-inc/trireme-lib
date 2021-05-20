package k8smonitor

import (
	"context"
	"fmt"

	"go.aporeto.io/enforcerd/internal/extractors/containermetadata"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/external"

	"go.uber.org/zap"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ external.ReceiveEvents = &K8sMonitor{}

func (m *K8sMonitor) isCniInstalledOrRuncProxyStarted() bool {
	m.extMonitorStartedLock.RLock()
	defer m.extMonitorStartedLock.RUnlock()
	return m.cniInstalledOrRuncProxyStarted
}

// SenderReady will be called by the sender to notify the receiver that the sender
// is now ready to send events.
func (m *K8sMonitor) SenderReady() {
	m.extMonitorStartedLock.Lock()
	m.cniInstalledOrRuncProxyStarted = true
	m.extMonitorStartedLock.Unlock()
	close(m.cniInstalledOrRuncProxyStartedCh)
	zap.L().Debug("K8sMonitor: CNI plugin is installed and configured or runc-proxy has started")
}

// Event will receive event `data` for processing a common.Event in the monitor.
// The sent data is implementation specific - therefore it has no type in the interface.
// If the sent data is of an unexpected type, its implementor must return an error
// indicating so.
func (m *K8sMonitor) Event(ctx context.Context, ev common.Event, data interface{}) error {
	// the data is expected to be of type
	kmd, ok := data.(containermetadata.CommonKubernetesContainerMetadata)
	if !ok {
		return fmt.Errorf("K8sMonitor: invalid data type: %T", data)
	}

	switch ev {
	case common.EventStart:
		if err := m.startEvent(ctx, kmd, 0); err != nil {
			// TODO: handle retries that we can handle
			return fmt.Errorf("K8sMonitor: startEvent: %s", err)
		}
	case common.EventDestroy:
		if err := m.destroyEvent(ctx, kmd); err != nil {
			return fmt.Errorf("K8sMonitor: destroyEvent: %s", err)
		}
	default:
		return fmt.Errorf("K8sMonitor: unexpected event %s", ev)
	}
	return nil
}

type startEventFunc func(context.Context, containermetadata.CommonKubernetesContainerMetadata, uint) error

func (m *K8sMonitor) startEvent(ctx context.Context, kmd containermetadata.CommonKubernetesContainerMetadata, retry uint) error {
	switch kmd.Kind() {
	case containermetadata.PodSandbox:
		zap.L().Debug("K8sMonitor: startEvent: PodSandbox", zap.String("sandboxID", kmd.ID()), zap.String("podName", kmd.PodName()), zap.String("podNamespace", kmd.PodNamespace()))
		// get pod
		pod, err := m.getPod(ctx, kmd.PodNamespace(), kmd.PodName())
		if err != nil {
			// fire off a retry for this, but simply return with the error
			go m.startEventRetry(kmd, retry+1)
			return err
		}
		// this should never happen, but if it does, simply return
		if pod.Spec.HostNetwork {
			return nil
		}
		if err := m.podCache.Set(kmd.ID(), pod); err != nil {
			return err
		}

		// metadata exraction
		runtime, err := m.metadataExtractor(ctx, pod, kmd.NetNSPath())
		if err != nil {
			return err
		}
		if err := m.runtimeCache.Set(kmd.ID(), runtime); err != nil {
			return err
		}

		return m.handlers.Policy.HandlePUEvent(ctx, kmd.ID(), common.EventStart, runtime)

	case containermetadata.PodContainer:
		zap.L().Debug("K8sMonitor: startEvent: PodContainer", zap.String("id", kmd.ID()), zap.String("sandboxID", kmd.PodSandboxID()), zap.String("podName", kmd.PodName()), zap.String("podNamespace", kmd.PodNamespace()))
		// as we don't handle host network containers, this is a noop
		return nil
	default:
		return fmt.Errorf("K8sMonitor: unexpected container kind for start event: %s", kmd.Kind())
	}
}

type destroyEventFunc func(context.Context, containermetadata.CommonKubernetesContainerMetadata) error

func (m *K8sMonitor) destroyEvent(ctx context.Context, kmd containermetadata.CommonKubernetesContainerMetadata) error {
	switch kmd.Kind() {
	case containermetadata.PodSandbox:
		zap.L().Debug("K8sMonitor: destroyEvent: PodSandbox", zap.String("sandboxID", kmd.ID()))
		runtime := m.runtimeCache.Get(kmd.ID())
		if runtime == nil {
			// destroy event was sent previously, not a problem, just return
			zap.L().Debug("K8sMonitor: destroyEvent: sandbox not in runtime cache")
			return nil
		}

		// simply delete it from the caches and send a destroy event
		// even if that fails in the policy engine, there is nothing we can do about it
		m.runtimeCache.Delete(kmd.ID())
		m.podCache.Delete(kmd.ID())
		return m.handlers.Policy.HandlePUEvent(ctx, kmd.ID(), common.EventDestroy, runtime)

	case containermetadata.PodContainer:
		// if this is a container event that belongs to an existing sandbox
		// we can simply return, we don't need to do anything
		return nil

	default:
		return fmt.Errorf("K8sMonitor: unexpected container kind for destroy event: %s", kmd.Kind())
	}
}

type stopEventFunc func(context.Context, string) error

func (m *K8sMonitor) stopEvent(ctx context.Context, sandboxID string) error {
	zap.L().Debug("K8sMonitor: stopEvent", zap.String("sandboxID", sandboxID))
	runtime := m.runtimeCache.Get(sandboxID)
	if runtime == nil {
		// destroy event had been sent already, not a problem, simply return
		zap.L().Debug("K8sMonitor: stopEvent: sandbox not in runtime cache")
		return nil
	}

	return m.handlers.Policy.HandlePUEvent(ctx, sandboxID, common.EventStop, runtime)
}

type updateEventFunc func(context.Context, string) error

func (m *K8sMonitor) updateEvent(ctx context.Context, sandboxID string) error {
	zap.L().Debug("K8sMonitor: updateEvent", zap.String("sandboxID", sandboxID))
	runtime := m.runtimeCache.Get(sandboxID)
	if runtime == nil {
		// destroy event had been sent already, not a problem, simply return
		zap.L().Debug("K8sMonitor: updateEvent: sandbox not in runtime cache")
		return nil
	}

	pod := m.podCache.Get(sandboxID)
	if pod == nil {
		// destroy event had been sent already, not a problem, simply return
		zap.L().Debug("K8sMonitor: updateEvent: pod not in pod cache")
		return nil
	}

	// run metadata extraction again
	// don't forget to update the runtime cache
	runtime, err := m.metadataExtractor(ctx, pod, runtime.NSPath())
	if err != nil {
		return err
	}
	if err := m.runtimeCache.Set(sandboxID, runtime); err != nil {
		return err
	}

	// send an update event
	return m.handlers.Policy.HandlePUEvent(ctx, sandboxID, common.EventUpdate, runtime)
}

// getPod tries to get the pod from the internal informer cache first, and falls back to the Kubernetes API if that fails
// the cache is being kept up-to-date by Kubernetes internals, we don't need to care about this
// NOTE: do not confuse the informer cache with the podCache from this package!
func (m *K8sMonitor) getPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	pod, err := m.podLister.Pods(namespace).Get(name)
	if err != nil {
		zap.L().Debug("K8sMonitor: getPod: failed to get pod from cache. Using Kubernetes API directly now instead...", zap.String("name", name), zap.String("namespace", namespace), zap.Error(err))
		return m.kubeClient.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	}
	return pod, nil
}
