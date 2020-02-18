// +build linux !windows

package podmonitor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sasha-s/go-deadlock"
	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"go.uber.org/zap"
)

// ResyncWithAllPods is called from the implemented resync, it will list all pods
// and fire them down the event source (the generic event channel).
// It will block until every pod at the time of calling has been calling `Reconcile` at least once.
func ResyncWithAllPods(ctx context.Context, c client.Client, i *ResyncInfoChan, evCh chan<- event.GenericEvent, nodeName string) error {
	zap.L().Debug("Pod resync: starting to resync all pods")
	if c == nil {
		return errors.New("pod: no client available")
	}

	if evCh == nil {
		return errors.New("pod: no event source available")
	}

	if i == nil {
		return errors.New("pod: no resync info channel available")
	}

	list := &corev1.PodList{}
	if err := c.List(ctx, &client.ListOptions{}, list); err != nil {
		return fmt.Errorf("pod: %s", err.Error())
	}

	// build a map of pods that we will expect to turn true
	m := make(map[string]bool)
	for _, pod := range list.Items {
		if pod.Spec.NodeName != nodeName {
			continue
		}
		podName := pod.GetName()
		podNamespace := pod.GetNamespace()
		if podName != "" && podNamespace != "" {
			m[fmt.Sprintf("%s/%s", podNamespace, podName)] = false
		}
	}
	zap.L().Debug("Pod resync: pods that need to be resynced", zap.Any("pods", m))

	// Request that the controller reports to us from now on
	i.EnableNeedsInfo()

	// fire away events to the controller
	for _, pod := range list.Items {
		if pod.Spec.NodeName != nodeName {
			continue
		}
		p := pod.DeepCopy()
		evCh <- event.GenericEvent{
			Meta:   p.GetObjectMeta(),
			Object: p,
		}
	}

	// now wait for all pods to have reported back
	begin := time.Now()
waitLoop:
	for {
		if time.Since(begin) > (time.Second * 60) {
			zap.L().Warn("Pod resync: failed to reconcile on all pods. Unblocking now anyway.")
			break waitLoop
		}

		select {
		case info := <-*i.GetInfoCh():
			if _, ok := m[info]; ok {
				zap.L().Debug("Pod resync: pod that is part of the resync", zap.String("pod", info))
				m[info] = true
			} else {
				zap.L().Debug("Pod resync: *not* a pod that is part of the resync", zap.String("pod", info))
			}
		case <-time.After(time.Second * 5):
			zap.L().Debug("Pod resync: timeout waiting for pod reconcile")
		}

		// now check if we can abort already
		for _, v := range m {
			if !v {
				continue waitLoop
			}
		}
		break waitLoop
	}
	i.DisableNeedsInfo()
	zap.L().Debug("Pod resync: finished resyncing all pods")

	return nil
}

// ResyncInfoChan is used to report back from the controller on which pods it has processed.
// It allows the Resync of the monitor to block and wait until a list has been processed.
type ResyncInfoChan struct {
	m  deadlock.RWMutex
	b  bool
	ch chan string
}

// NewResyncInfoChan creates a new ResyncInfoChan
func NewResyncInfoChan() *ResyncInfoChan {
	return &ResyncInfoChan{
		ch: make(chan string, 100),
	}
}

// EnableNeedsInfo enables the need for sending info
func (r *ResyncInfoChan) EnableNeedsInfo() {
	r.m.Lock()
	defer r.m.Unlock()
	r.b = true
}

// DisableNeedsInfo disables the need for sending info
func (r *ResyncInfoChan) DisableNeedsInfo() {
	r.m.Lock()
	defer r.m.Unlock()
	r.b = false
}

// NeedsInfo returns if there is a need for sending info
func (r *ResyncInfoChan) NeedsInfo() bool {
	r.m.RLock()
	defer r.m.RUnlock()
	return r.b
}

// SendInfo will make the info available through an internal channel
func (r *ResyncInfoChan) SendInfo(info string) {
	r.m.RLock()
	defer r.m.RUnlock()
	if r.b {
		r.ch <- info
	}
}

// GetInfoCh returns the channel
func (r *ResyncInfoChan) GetInfoCh() *chan string {
	r.m.RLock()
	defer r.m.RUnlock()
	return &r.ch
}
