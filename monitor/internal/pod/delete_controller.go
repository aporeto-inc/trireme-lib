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

// DeleteController is responsible for cleaning up after Kubernetes because we
// are missing our native ID on the last reconcile event where the pod has already
// been deleted. This is also more reliable because we are filling this controller
// with events starting from the time when we first see a deletion timestamp on a pod.
// It pretty much facilitates the work of a finalizer without needing a finalizer and
// also only kicking in once a pod has *really* been deleted.
type DeleteController struct {
	client      client.Client
	handler     *config.ProcessorConfig
	deleteCh    <-chan DeleteEvent
	reconcileCh <-chan struct{}
}

// Start implemets the Runnable interface
func (c *DeleteController) Start(z <-chan struct{}) error {
	backgroundCtx := context.Background()
	t := time.NewTicker(time.Second * 5)
	m := make(map[string]client.ObjectKey)

	// this is our reconcile function: either triggered by a real event or the timer
	reconcile := func() {
		for nativeID, req := range m {
			// we'll give one item in the list up to 10 seconds
			ctx, cancel := context.WithTimeout(backgroundCtx, time.Second*10)
			pod := &corev1.Pod{}
			if err := c.client.Get(ctx, req, pod); err != nil {
				if errors.IsNotFound(err) {
					// this is the normal case: a pod is gone
					// so just send a destroy event
					if err := c.handler.Policy.HandlePUEvent(
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
					delete(m, nativeID)
				} else {
					// we don't really care, we just warn
					zap.L().Warn("failed to get pod from Kubernetes API", zap.String("puID", nativeID), zap.String("namespacedName", req.String()), zap.Error(err))
				}
			}

			// the edge case: a pod with the same namespaced name came up and we have missed a delete event
			// this means that this pod belongs to a different PU and must live, therefore we try to delete the old one
			if nativeID != string(pod.GetUID()) {
				zap.L().Error("Pod does not have expected native ID, we must have missed an event and the same pod was recreated. Trying to destroy PU", zap.String("puID", nativeID), zap.String("namespacedName", req.String()), zap.String("podUID", string(pod.GetUID())))
				if err := c.handler.Policy.HandlePUEvent(
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
				delete(m, nativeID)
			}

			// don't forget to cancel this context
			cancel()
		}
	}

	// the poor man's controller loop
	for {
		select {
		case ev := <-c.deleteCh:
			m[ev.NativeID] = ev.Key
		case <-c.reconcileCh:
			reconcile()
		case <-t.C:
			reconcile()
		case <-z:
			t.Stop()
			return nil
		}
	}
}
