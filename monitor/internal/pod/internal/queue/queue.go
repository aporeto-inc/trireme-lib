package queue

import (
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/policy"
	"k8s.io/apimachinery/pkg/types"
)

// PolicyEngineEvent holds all the event information for an event that we send to the policy engine
type PolicyEngineEvent struct {
	ID      types.UID
	Event   common.Event
	Runtime policy.RuntimeReader
}

// PolicyEngineQueue queues events to the policy engine and processes them in serial *per pod*
type PolicyEngineQueue struct {
	queue chan *PolicyEngineEvent
	pc    *config.ProcessorConfig
}

// NewPolicyEngineQueue creates a new policy engine queue
func NewPolicyEngineQueue(pc *config.ProcessorConfig, queueSize int) *PolicyEngineQueue {
	return &PolicyEngineQueue{
		pc:    pc,
		queue: make(chan *PolicyEngineEvent, queueSize),
	}
}

// Queue returns the channel that clients can use to send events to the policy engine
func (q *PolicyEngineQueue) Queue() chan<- *PolicyEngineEvent {
	return q.queue
}

// Start starts the queue and will block until z is closed
func (q *PolicyEngineQueue) Start(z <-chan struct{}) error {
	go q.loop()
	<-z
	return nil
}

func (q *PolicyEngineQueue) loop() {

}
