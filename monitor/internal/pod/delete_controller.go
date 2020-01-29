// +build !windows

package podmonitor

import (
	"context"
	"time"

	"go.aporeto.io/trireme-lib/v11/common"
	"go.aporeto.io/trireme-lib/v11/monitor/config"
	"go.aporeto.io/trireme-lib/v11/monitor/extractors"
	"go.aporeto.io/trireme-lib/v11/policy"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

// deleteControllerReconcileFunc is the reconciler function signature for the DeleteController
type deleteControllerReconcileFunc func(context.Context, client.Client, string, *config.ProcessorConfig, time.Duration, map[string]DeleteObject, extractors.PodSandboxExtractor, chan event.GenericEvent)

// DeleteController is responsible for cleaning up after Kubernetes because we
// are missing our native ID on the last reconcile event where the pod has already
// been deleted. This is also more reliable because we are filling this controller
// with events starting from the time when we first see a deletion timestamp on a pod.
// It pretty much facilitates the work of a finalizer without needing a finalizer and
// also only kicking in once a pod has *really* been deleted.
type DeleteController struct {
	client   client.Client
	nodeName string
	handler  *config.ProcessorConfig

	deleteCh           chan DeleteEvent
	reconcileCh        chan struct{}
	reconcileFunc      deleteControllerReconcileFunc
	tickerPeriod       time.Duration
	itemProcessTimeout time.Duration
	sandboxExtractor   extractors.PodSandboxExtractor
	eventsCh           chan event.GenericEvent
}

// DeleteObject is the obj used to store in the event map.
type DeleteObject struct {
	podUID    string
	sandboxID string
	podName   client.ObjectKey
}

// NewDeleteController creates a new DeleteController.
func NewDeleteController(c client.Client, nodeName string, pc *config.ProcessorConfig, sandboxExtractor extractors.PodSandboxExtractor, eventsCh chan event.GenericEvent) *DeleteController {
	return &DeleteController{
		client:             c,
		nodeName:           nodeName,
		handler:            pc,
		deleteCh:           make(chan DeleteEvent, 1000),
		reconcileCh:        make(chan struct{}),
		reconcileFunc:      deleteControllerReconcile,
		tickerPeriod:       5 * time.Second,
		itemProcessTimeout: 30 * time.Second,
		sandboxExtractor:   sandboxExtractor,
		eventsCh:           eventsCh,
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
			obj := DeleteObject{podUID: ev.PodUID, sandboxID: ev.SandboxID, podName: ev.NamespaceName}
			// here don't update the map, insert only if not present.
			if _, ok := m[ev.PodUID]; !ok {
				m[ev.PodUID] = obj
			}
		case <-c.reconcileCh:
			c.reconcileFunc(backgroundCtx, c.client, c.nodeName, c.handler, c.itemProcessTimeout, m, c.sandboxExtractor, c.eventsCh)
		case <-t.C:
			c.reconcileFunc(backgroundCtx, c.client, c.nodeName, c.handler, c.itemProcessTimeout, m, c.sandboxExtractor, c.eventsCh)
		case <-z:
			t.Stop()
			return nil
		}
	}
}

// deleteControllerReconcile is the real reconciler implementation for the DeleteController
func deleteControllerReconcile(backgroundCtx context.Context, c client.Client, nodeName string, pc *config.ProcessorConfig, itemProcessTimeout time.Duration, m map[string]DeleteObject, sandboxExtractor extractors.PodSandboxExtractor, eventCh chan event.GenericEvent) {
	for podUID, req := range m {
		deleteControllerProcessItem(backgroundCtx, c, nodeName, pc, itemProcessTimeout, m, podUID, req.podName, sandboxExtractor, eventCh)
	}
}

func deleteControllerProcessItem(backgroundCtx context.Context, c client.Client, nodeName string, pc *config.ProcessorConfig, itemProcessTimeout time.Duration, m map[string]DeleteObject, podUID string, req client.ObjectKey, sandboxExtractor extractors.PodSandboxExtractor, eventCh chan event.GenericEvent) {
	var ok bool
	var delObj DeleteObject
	if delObj, ok = m[podUID]; !ok {
		zap.L().Warn("DeleteController: nativeID not found in delete controller map", zap.String("nativeID", podUID))
		return
	}
	ctx, cancel := context.WithTimeout(backgroundCtx, itemProcessTimeout)
	defer cancel()
	pod := &corev1.Pod{}
	if err := c.Get(ctx, req, pod); err != nil {
		if errors.IsNotFound(err) {
			// this is the normal case: a pod is gone
			// so just send a destroy event
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
			// we don't really care, we just warn
			zap.L().Warn("DeleteController: Failed to get pod from Kubernetes API", zap.String("puID", podUID), zap.String("namespacedName", req.String()), zap.Error(err))
		}
		return
	}

	// For StatefulSets we need to account for another special case: pods that move between nodes *keep* the same UID, so they won't fit the check below.
	// However, we can simply double-check the node name in the same way how we already filter events in the watcher/monitor
	if pod.Spec.NodeName != nodeName {
		zap.L().Debug("DeleteController: the pod is now on a different node, send destroy event", zap.String("puID", podUID), zap.String("namespacedName", req.String()), zap.String("podNodeName", pod.Spec.NodeName), zap.String("nodeName", nodeName))
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

		zap.L().Warn("DeleteController: Pod does not have expected native ID, we must have missed an event and the same pod was recreated. Trying to destroy PU", zap.String("puID", podUID), zap.String("namespacedName", req.String()), zap.String("podUID", string(pod.GetUID())))
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

	// now the 2nd case, when pod UID match
	if string(pod.UID) == delObj.podUID {
		zap.L().Debug("DeleteController: the pod UID Match happened, delete the", zap.String("podName:", req.String()), zap.String("podUID", string(pod.UID)))
		// 2a get the current sandboxID
		if sandboxExtractor == nil {
			return
		}
		currentSandboxID, err := sandboxExtractor(ctx, pod)
		if err != nil {
			zap.L().Debug("DeleteController: cannot extract the SandboxID, return", zap.String("namespacedName", req.String()), zap.String("podUID", string(pod.GetUID())))
			return
		}
		// update the map with the sandboxID
		// here we update the map only if the sandboxID has not been extracted.
		// The extraction of the sandboxID if  missed by the main controller then we will update the map below.
		if delObj.sandboxID == "" {
			delObj = DeleteObject{podUID: podUID, sandboxID: currentSandboxID, podName: req}
			m[podUID] = delObj
		}
		// 2b get the pod/old sandboxID
		oldSandboxID := delObj.sandboxID

		zap.L().Debug("DeleteController:", zap.String(" the sandboxID, curr:", currentSandboxID), zap.String(" old sandboxID: ", oldSandboxID))
		// 2c compare the oldSandboxID and currentSandboxID, if they differ then destroy the PU
		if oldSandboxID != currentSandboxID {
			zap.L().Debug("DeleteController: Pod SandboxID differ. Trying to destroy PU", zap.String("namespacedName", req.String()), zap.String("currentSandboxID", currentSandboxID), zap.String("oldSandboxID", oldSandboxID))
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
			zap.L().Debug("DeleteController: PU destroyed, now send event for the pod-controller to reconcile", zap.String(" podName: ", req.String()))
			// below we send event to the main pod-controller to reconcile again and to create a PU if it is not created yet.
			eventCh <- event.GenericEvent{
				Object: pod,
				Meta:   pod.GetObjectMeta(),
			}
			return
		}
	}
}
