package queue

import (
	"context"

	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"k8s.io/client-go/tools/record"
)

// ensure NoqueuePolicyEngineQueue implements PolicyEngineQueue
var _ PolicyEngineQueue = &NoqueuePolicyEngineQueue{}

// NoqueuePolicyEngineQueue queues events to the policy engine and processes them in serial
type NoqueuePolicyEngineQueue struct {
	pc               *config.ProcessorConfig
	netclsProgrammer extractors.PodNetclsProgrammer
	recorder         record.EventRecorder
}

// Enqueue implements PolicyEngineQueue. For the NoqueuePolicyEngineQueue it will actually
// not queue at all and just simple process the event while enqueuing.
func (q *NoqueuePolicyEngineQueue) Enqueue(ctx context.Context, ev *PolicyEngineEvent) error {
	return processEvent(ctx, q.pc.Policy, q.netclsProgrammer, q.recorder, ev)
}

// Start starts the queue and will block until z is closed
func (q *NoqueuePolicyEngineQueue) Start(z <-chan struct{}) error {
	<-z
	return nil
}
