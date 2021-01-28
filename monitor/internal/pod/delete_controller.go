// +build !windows

package podmonitor

import (
	"context"
	"time"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

// deleteControllerReconcileFunc is the reconciler function signature for the DeleteController
type deleteControllerReconcileFunc func(context.Context, client.Client, kubernetes.Interface, string, *config.ProcessorConfig, time.Duration, map[string]DeleteObject, extractors.PodSandboxExtractor, chan event.GenericEvent, uint8)

// DeleteController is responsible for cleaning up after Kubernetes because we
// are missing our native ID on the last reconcile event where the pod has already
// been deleted. This is also more reliable because we are filling this controller
// with events starting from the time when we first see a deletion timestamp on a pod.
// It pretty much facilitates the work of a finalizer without needing a finalizer and
// also only kicking in once a pod has *really* been deleted.
type DeleteController struct {
	client        client.Client
	vanillaClient kubernetes.Interface

	nodeName string
	handler  *config.ProcessorConfig

	deleteCh           chan DeleteEvent
	reconcileCh        chan struct{}
	reconcileFunc      deleteControllerReconcileFunc
	tickerPeriod       time.Duration
	itemProcessTimeout time.Duration
	sandboxExtractor   extractors.PodSandboxExtractor
	eventsCh           chan event.GenericEvent
	retryCounter       uint8
}

// DeleteObject is the obj used to store in the event map.
type DeleteObject struct {
	podUID          string
	sandboxID       string
	podName         client.ObjectKey
	getRetryCounter uint8
}

// NewDeleteController creates a new DeleteController.
func NewDeleteController(c client.Client, vc kubernetes.Interface, nodeName string, pc *config.ProcessorConfig, sandboxExtractor extractors.PodSandboxExtractor, eventsCh chan event.GenericEvent, initialGetRetryCount uint8) *DeleteController {
	return &DeleteController{
		client:             c,
		vanillaClient:      vc,
		nodeName:           nodeName,
		handler:            pc,
		deleteCh:           make(chan DeleteEvent, 1000),
		reconcileCh:        make(chan struct{}),
		reconcileFunc:      deleteControllerReconcile,
		tickerPeriod:       5 * time.Second,
		itemProcessTimeout: 30 * time.Second,
		sandboxExtractor:   sandboxExtractor,
		eventsCh:           eventsCh,
		retryCounter:       initialGetRetryCount,
	}
}

// GetDeleteCh returns the delete channel on which to queue delete events
func (c *DeleteController) GetDeleteCh() chan<- DeleteEvent {
	return c.deleteCh
}

// GetReconcileCh returns the channel on which to notify the controller about an immediate reconcile event
func (c *DeleteController) GetReconcileCh() chan<- struct{} {
	return c.reconcileCh
}

// Start implemets the Runnable interface
func (c *DeleteController) Start(z <-chan struct{}) error {
	backgroundCtx := context.Background()
	t := time.NewTicker(c.tickerPeriod)
	m := make(map[string]DeleteObject)

	// the poor man's controller loop
	for {
		select {
		case ev := <-c.deleteCh:
			obj := DeleteObject{podUID: ev.PodUID, sandboxID: ev.SandboxID, podName: ev.NamespaceName, getRetryCounter: c.retryCounter}
			// here don't update the map, insert only if not present.
			if _, ok := m[ev.PodUID]; !ok {
				m[ev.PodUID] = obj
			}
		case <-c.reconcileCh:
			c.reconcileFunc(backgroundCtx, c.client, c.vanillaClient, c.nodeName, c.handler, c.itemProcessTimeout, m, c.sandboxExtractor, c.eventsCh, c.retryCounter)
		case <-t.C:
			c.reconcileFunc(backgroundCtx, c.client, c.vanillaClient, c.nodeName, c.handler, c.itemProcessTimeout, m, c.sandboxExtractor, c.eventsCh, c.retryCounter)
		case <-z:
			t.Stop()
			return nil
		}
	}
}

// deleteControllerReconcile is the real reconciler implementation for the DeleteController
func deleteControllerReconcile(backgroundCtx context.Context, c client.Client, vc kubernetes.Interface, nodeName string, pc *config.ProcessorConfig, itemProcessTimeout time.Duration, m map[string]DeleteObject, sandboxExtractor extractors.PodSandboxExtractor, eventCh chan event.GenericEvent, maxGetRetryCount uint8) {
	for podUID, req := range m {
		deleteControllerProcessItem(backgroundCtx, c, vc, nodeName, pc, itemProcessTimeout, m, podUID, req.podName, sandboxExtractor, eventCh, maxGetRetryCount)
	}
}

func deleteControllerProcessItem(backgroundCtx context.Context, c client.Client, vc kubernetes.Interface, nodeName string, pc *config.ProcessorConfig, itemProcessTimeout time.Duration, m map[string]DeleteObject, podUID string, req client.ObjectKey, sandboxExtractor extractors.PodSandboxExtractor, eventCh chan event.GenericEvent, maxGetRetryCount uint8) {
	var ok bool
	var delObj DeleteObject
	if delObj, ok = m[podUID]; !ok {
		zap.L().Warn("DeleteController: nativeID not found in delete controller map", zap.String("nativeID", podUID))
		return
	}

	// The controller-runtime cache seems to be faulty from time to time.
	// However, we cannot afford mistakes here which is why we are using
	// the vanilla/standard golang Kubernetes client instead (even though it is uncached).
	// Unfortunately, in older versions of the client, it does not support
	// proper context handling, which is why we are wrapping this in a
	// function that aborts after a context timeout. Note though that this
	// also means that this could potentially eat up go routines if it would
	// never time out. However, it is safe to assume that this will not be
	// the case.
	ctx, cancel := context.WithTimeout(backgroundCtx, itemProcessTimeout)
	defer cancel()

	getControllerRuntimePod := func(ctx context.Context) (*corev1.Pod, error) {
		pod := &corev1.Pod{}
		if err := c.Get(ctx, req, pod); err != nil {
			return nil, err
		}
		return pod, nil
	}

	getVanillaClientPod := func(ctx context.Context) (*corev1.Pod, error) {
		chPod := make(chan *corev1.Pod)
		chErr := make(chan error)
		go func() {
			pod, err := vc.CoreV1().Pods(req.Namespace).Get(req.Name, metav1.GetOptions{})
			if err != nil {
				chErr <- err
			}
			chPod <- pod
		}()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case err := <-chErr:
			return nil, err
		case pod := <-chPod:
			return pod, nil
		}
	}

	getPod := func(ctx context.Context) (*corev1.Pod, error) {
		pod, err := getControllerRuntimePod(ctx)
		if err != nil {
			if errors.IsNotFound(err) {
				// double-check by using the vanilla client as well
				pod, err2 := getVanillaClientPod(ctx)
				if err2 != nil {
					return nil, err2
				}
				zap.L().Warn("DeleteController: pod not found in Kubernetes API using controller-runtime client, but found with vanilla client", zap.String("puID", podUID), zap.String("namespacedName", req.String()), zap.Error(err))
				return pod, nil
			}
			return nil, err
		}
		return pod, nil
	}

	pod, err := getPod(ctx)
	if err != nil {
		if errors.IsNotFound(err) {
			// this is usually just the normal case: a pod is gone
			// however, we have a retry counter because we have seen inconsisten results for API requests before here
			// so we retry until this counter is zero
			if delObj.getRetryCounter == 0 {
				// then just send a destroy event
				zap.L().Info("DeleteController: pod not found in the Kubernetes API, sending destroy event for the PU", zap.String("puID", podUID), zap.String("namespacedName", req.String()), zap.Error(err))
				if err := pc.Policy.HandlePUEvent(
					ctx,
					podUID,
					common.EventDestroy,
					policy.NewPURuntimeWithDefaults(),
				); err != nil {
					// we don't really care, we just warn
					zap.L().Warn("DeleteController: Failed to handle destroy event", zap.String("puID", podUID), zap.String("namespacedName", req.String()), zap.Error(err))
				}
				// we only fire events away, we don't really care about the error anyway
				// it is up to the policy engine to make sense of that
				delete(m, podUID)
			} else {
				// otherwise we decrease this counter
				delObj.getRetryCounter -= 1
				m[podUID] = delObj
				zap.L().Info("DeleteController: pod not found in the Kubernetes API, decreased retry counter before we send a destroy event for this PU", zap.String("puID", podUID), zap.String("namespacedName", req.String()), zap.Uint8("getRetryCounter", delObj.getRetryCounter), zap.Error(err))
			}
		} else {
			// we don't really care, we just warn
			zap.L().Warn("DeleteController: failed to get pod from Kubernetes API", zap.String("puID", podUID), zap.String("namespacedName", req.String()), zap.Error(err))
		}
		return
	}

	// we need to account/warn for the case when we found the pod again, although we previously already thought it was gone
	if delObj.getRetryCounter < maxGetRetryCount {
		zap.L().Warn("DeleteController: this pod was previously observed to be gone from the Kubernetes API, however, it reappeared. You might have inconsistencies in your Kubernetes database. Resetting retry counter.", zap.String("puID", podUID), zap.String("namespacedName", req.String()), zap.Uint8("getRetryCounter", delObj.getRetryCounter), zap.Uint8("maxGetRetryCount", maxGetRetryCount))
		delObj.getRetryCounter = maxGetRetryCount
		m[podUID] = delObj
	}

	// For StatefulSets we need to account for another special case: pods that move between nodes *keep* the same UID, so they won't fit the check below.
	// However, we can simply double-check the node name in the same way how we already filter events in the watcher/monitor
	if pod.Spec.NodeName != nodeName {
		zap.L().Warn("DeleteController: the pod is now on a different node, send destroy event and delete the cache", zap.String("puID", podUID), zap.String("namespacedName", req.String()), zap.String("podNodeName", pod.Spec.NodeName), zap.String("nodeName", nodeName))
		if err := pc.Policy.HandlePUEvent(
			ctx,
			podUID,
			common.EventDestroy,
			policy.NewPURuntimeWithDefaults(),
		); err != nil {
			// we don't really care, we just warn
			zap.L().Warn("DeleteController: Failed to handle destroy event", zap.String("puID", podUID), zap.String("namespacedName", req.String()), zap.Error(err))
		}
		// we only fire events away, we don't really care about the error anyway
		// it is up to the policy engine to make sense of that
		delete(m, podUID)
		return
	}

	// the edge case: a pod with the same namespaced name came up and we have missed a delete event
	// this means that this pod belongs to a different PU and must live, therefore we try to delete the old one

	// the following code also takes care of any restarts in the Pod, the restarts can be caused by either
	// the sandbox getting killed or all the containers restarting due a crash or kill.

	// Now destroy the PU only if the following
	// 1. Simple case if the pod UID don't match then go ahead and destroy the PU.
	// 2. When the pod UID match then do the following:
	//		2.a Get the current SandboxID from the pod.
	// 		2.b Get the sandboxID from the map.
	// 		2.c If the sandBoxID differ then send the destroy event for the old(map) sandBoxID.

	// 1st case, simple if the pod UID don't match then just call the destroy PU event and delete the map entry with the old key.
	if string(pod.UID) != delObj.podUID {

		zap.L().Warn("DeleteController: pod does not have expected pod UID (puID), we must have missed an event and the same pod was recreated. Sending destroy event for PU", zap.String("puID", podUID), zap.String("namespacedName", req.String()), zap.String("podUID", string(pod.GetUID())))
		if err := pc.Policy.HandlePUEvent(
			ctx,
			podUID,
			common.EventDestroy,
			policy.NewPURuntimeWithDefaults(),
		); err != nil {
			// we don't really care, we just warn
			zap.L().Warn("DeleteController: failed to handle destroy event", zap.String("puID", podUID), zap.String("namespacedName", req.String()), zap.Error(err))
		}
		// we only fire events away, we don't really care about the error anyway
		// it is up to the policy engine to make sense of that
		delete(m, podUID)
		return
	}

	// now the 2nd case, when pod UID match
	if string(pod.UID) == delObj.podUID {
		// 2a get the current sandboxID
		if sandboxExtractor == nil {
			return
		}
		currentSandboxID, err := sandboxExtractor(ctx, pod)
		if err != nil {
			zap.L().Debug("DeleteController: failed to extract sandbox ID, abort and will retry", zap.String("namespacedName", req.String()), zap.String("podUID", string(pod.GetUID())))
			return
		}
		// update the map with the sandboxID
		// here we update the map only if the sandboxID has not been extracted.
		// The extraction of the sandboxID if  missed by the main controller then we will update the map below.
		if delObj.sandboxID == "" {
			delObj = DeleteObject{podUID: podUID, sandboxID: currentSandboxID, podName: req, getRetryCounter: delObj.getRetryCounter}
			m[podUID] = delObj
		}
		// 2b get the pod/old sandboxID
		oldSandboxID := delObj.sandboxID

		// 2c compare the oldSandboxID and currentSandboxID, if they differ then destroy the PU
		if oldSandboxID != currentSandboxID {
			zap.L().Warn("DeleteController: pod sandbox differs. Sending destroy event for PU", zap.String("puID", podUID), zap.String("namespacedName", req.String()), zap.String("currentSandboxID", currentSandboxID), zap.String("oldSandboxID", oldSandboxID))
			if err := pc.Policy.HandlePUEvent(
				ctx,
				podUID,
				common.EventDestroy,
				policy.NewPURuntimeWithDefaults(),
			); err != nil {
				// we don't really care, we just warn
				zap.L().Warn("DeleteController: failed to handle destroy event", zap.String("puID", podUID), zap.String("namespacedName", req.String()), zap.Error(err))
			}
			// we only fire events away, we don't really care about the error anyway
			// it is up to the policy engine to make sense of that
			delete(m, podUID)
			zap.L().Warn("DeleteController: sent PU destroy event, now send an event to the pod-controller to reconcile and recreate a new PU", zap.String("puID", podUID), zap.String("namespacedName", req.String()))
			// below we send event to the main pod-controller to reconcile again and to create a PU if it is not created yet.
			eventCh <- event.GenericEvent{
				Object: pod,
				Meta:   pod.GetObjectMeta(),
			}
			return
		}
	}
}
