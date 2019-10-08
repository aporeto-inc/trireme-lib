package queue

import (
	"context"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/policy"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
)

// PolicyEngineQueue defines the interface for interacting with a policy engine queue
type PolicyEngineQueue interface {
	// Enqueue can be used to put policy engine events into the queue for processing.
	// NOTE: This does not return a channel which can be used for queueing events on purpose.
	// Implementations should put the events into their queue as fast as possible, and return
	// with an error only if there was a problem with queuing the event.
	// This model of enqueuing is used to allow for certain specific implementations.
	Enqueue(context.Context, *PolicyEngineEvent) error

	// Start should start the queue and prepare it for receiving events. The queue should be
	// ready to receive events after `Start` has been called.
	Start(<-chan struct{}) error
}

// PolicyEngineEvent holds all the event information for an event that we send to the policy engine.
type PolicyEngineEvent struct {
	ID      types.UID
	Event   common.Event
	Runtime policy.RuntimeReader
	Pod     *corev1.Pod
}

// NewPolicyEngineQueue creates a new policy engine queue
func NewPolicyEngineQueue(pc *config.ProcessorConfig, queueSize int, netclsProgrammer extractors.PodNetclsProgrammer, recorder record.EventRecorder) PolicyEngineQueue {

	return &SimplePolicyEngineQueue{
		pc:               pc,
		netclsProgrammer: netclsProgrammer,
		recorder:         recorder,
		queue:            make(chan *PolicyEngineEvent, queueSize),
	}
}
