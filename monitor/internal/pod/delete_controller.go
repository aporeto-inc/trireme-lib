package podmonitor

import (
	"context"
	"time"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// deleteControllerReconcileFunc is the reconciler function signature for the DeleteController
type deleteControllerReconcileFunc func(context.Context, client.Client, *config.ProcessorConfig, time.Duration, *map[string]client.ObjectKey)

// DeleteController is responsible for cleaning up after Kubernetes because we
// are missing our native ID on the last reconcile event where the pod has already
// been deleted. This is also more reliable because we are filling this controller
// with events starting from the time when we first see a deletion timestamp on a pod.
// It pretty much facilitates the work of a finalizer without needing a finalizer and
// also only kicking in once a pod has *really* been deleted.
type DeleteController struct {
	client  client.Client
	handler *config.ProcessorConfig

	deleteCh           chan DeleteEvent
	reconcileCh        chan struct{}
	reconcileFunc      deleteControllerReconcileFunc
	tickerPeriod       time.Duration
	itemProcessTimeout time.Duration
}

// NewDeleteController creates a new DeleteController.
func NewDeleteController(c client.Client, pc *config.ProcessorConfig) *DeleteController {
	return &DeleteController{
		client:             c,
		handler:            pc,
		deleteCh:           make(chan DeleteEvent, 1000),
		reconcileCh:        make(chan struct{}),
		reconcileFunc:      deleteControllerReconcile,
		tickerPeriod:       time.Duration(5 * time.Second),
		itemProcessTimeout: time.Duration(30 * time.Second),
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
	m := make(map[string]client.ObjectKey)

	// the poor man's controller loop
	for {
		select {
		case ev := <-c.deleteCh:
			m[ev.NativeID] = ev.Key
		case <-c.reconcileCh:
			c.reconcileFunc(backgroundCtx, c.client, c.handler, c.itemProcessTimeout, &m)
		case <-t.C:
			c.reconcileFunc(backgroundCtx, c.client, c.handler, c.itemProcessTimeout, &m)
		case <-z:
			t.Stop()
			return nil
		}
	}
}

// deleteControllerReconcile is the real reconciler implementation for the DeleteController
func deleteControllerReconcile(backgroundCtx context.Context, c client.Client, pc *config.ProcessorConfig, itemProcessTimeout time.Duration, m *map[string]client.ObjectKey) {
	for nativeID, req := range *m {
		deleteControllerProcessItem(backgroundCtx, c, pc, itemProcessTimeout, m, nativeID, req)
	}
}

func deleteControllerProcessItem(backgroundCtx context.Context, c client.Client, pc *config.ProcessorConfig, itemProcessTimeout time.Duration, m *map[string]client.ObjectKey, nativeID string, req client.ObjectKey) {
	ctx, cancel := context.WithTimeout(backgroundCtx, itemProcessTimeout)
	defer cancel()
	pod := &corev1.Pod{}
	if err := c.Get(ctx, req, pod); err != nil {
		if errors.IsNotFound(err) {
			// this is the normal case: a pod is gone
			// so just send a destroy event
			if err := pc.Policy.HandlePUEvent(
				ctx,
				nativeID,
				common.EventDestroy,
				policy.NewPURuntimeWithDefaults(),
			); err != nil {
				// we don't really care, we just warn
				zap.L().Warn("failed to handle destroy event", zap.String("puID", nativeID), zap.String("namespacedName", req.String()), zap.Error(err))
			}
			// we only fire events away, we don't really care about the error anyway
			// it is up to the policy engine to make sense of that
			delete(*m, nativeID)
		} else {
			// we don't really care, we just warn
			zap.L().Warn("failed to get pod from Kubernetes API", zap.String("puID", nativeID), zap.String("namespacedName", req.String()), zap.Error(err))
		}
		return
	}

	// the edge case: a pod with the same namespaced name came up and we have missed a delete event
	// this means that this pod belongs to a different PU and must live, therefore we try to delete the old one
	if nativeID != string(pod.GetUID()) {
		zap.L().Error("Pod does not have expected native ID, we must have missed an event and the same pod was recreated. Trying to destroy PU", zap.String("puID", nativeID), zap.String("namespacedName", req.String()), zap.String("podUID", string(pod.GetUID())))
		if err := pc.Policy.HandlePUEvent(
			ctx,
			nativeID,
			common.EventDestroy,
			policy.NewPURuntimeWithDefaults(),
		); err != nil {
			// we don't really care, we just warn
			zap.L().Warn("failed to handle destroy event", zap.String("puID", nativeID), zap.String("namespacedName", req.String()), zap.Error(err))
		}
		// we only fire events away, we don't really care about the error anyway
		// it is up to the policy engine to make sense of that
		delete(*m, nativeID)
	}
	return
}
