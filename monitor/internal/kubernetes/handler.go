package kubernetes

import (
	"context"
	"fmt"

	"github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/policy"
)

// HandlePUEvent is called by all monitors when a PU event is generated. The implementer
// is responsible to update all components by explicitly adding a new PU.
// Specifically for Kubernetes, The monitor handles the downstream events from Docker.
func (m *KubernetesMonitor) HandlePUEvent(ctx context.Context, puID string, event common.Event, runtime policy.RuntimeReader) error {
	process, err := isPodContainer(runtime)
	if err != nil {
		return fmt.Errorf("Error while processing Kubernetes pod %s", err)
	}

	if !process {
		return nil
	}

	kubernetesRuntime, err := consolidateKubernetesTags(runtime)
	if err != nil {
		return fmt.Errorf("Error while processing Kubernetes pod %s", err)
	}

	return m.HandlePUEvent(ctx, puID, event, kubernetesRuntime)
}
