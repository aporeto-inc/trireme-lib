package podmonitor

import "sigs.k8s.io/controller-runtime/pkg/client"

// DeleteController is responsible for cleaning up after Kubernetes because we
// are missing our native ID on the last reconcile event where the pod has already
// been deleted. This is also more reliable because we are filling this controller
// with events starting from the time when we first see a deletion timestamp on a pod.
// It pretty much facilitates the work of a finalizer without needing a finalizer and
// also only kicking in once a pod has *really* been deleted.
type DeleteController struct {
	client client.Client
}

// Start implemets the Runnable interface
func (c *DeleteController) Start(z <-chan struct{}) error {

	<-z
	return nil
}
