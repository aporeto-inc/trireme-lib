package queue

import (
	"context"
	"time"

	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"k8s.io/client-go/tools/record"
)

// ensure SimplePolicyEngineQueue implements PolicyEngineQueue
var _ PolicyEngineQueue = &SimplePolicyEngineQueue{}

// SimplePolicyEngineQueue queues events to the policy engine and processes them in serial
type SimplePolicyEngineQueue struct {
	queue            chan *PolicyEngineEvent
	pc               *config.ProcessorConfig
	netclsProgrammer extractors.PodNetclsProgrammer
	recorder         record.EventRecorder
}

// Enqueue implements PolicyEngineQueue. It will simply put `ev` in its internal processing queue.
// If that is blocking because the queue is full, you need to pass a context with a timeout.
func (q *SimplePolicyEngineQueue) Enqueue(ctx context.Context, ev *PolicyEngineEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case q.queue <- ev:
		// successfully queued
		return nil
	}
}

// Start starts the queue and will block until z is closed
func (q *SimplePolicyEngineQueue) Start(z <-chan struct{}) error {
	go q.loop(z)
	<-z
	return nil
}

func (q *SimplePolicyEngineQueue) loop(z <-chan struct{}) {
loop:
	for {
		select {
		case <-z:
			break loop
		case ev := <-q.queue:
			q.process(ev)
		}
	}
}

func (q *SimplePolicyEngineQueue) process(ev *PolicyEngineEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	// we don't care about the error, everything that we can do is done inside of processEvent
	_ = processEvent(ctx, q.pc.Policy, q.netclsProgrammer, q.recorder, ev)
}
