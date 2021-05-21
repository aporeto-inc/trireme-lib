package external

import (
	"context"

	"go.aporeto.io/enforcerd/trireme-lib/common"
)

// ReceiveEvents can be implemented by monitors which receive their monitoring events
// for processing from different parts of the stack.
type ReceiveEvents interface {
	// Event will receive event `data` for processing a common.Event in the monitor.
	// The sent data is implementation specific - therefore it has no type in the interface.
	// If the sent data is of an unexpected type, its implementor must return an error
	// indicating so.
	Event(ctx context.Context, ev common.Event, data interface{}) error

	// SenderReady will be called by the sender to notify the receiver that the sender
	// is now ready to send events.
	SenderReady()
}

// ReceiverRegistration allows the trireme monitors to register themselves to receive events
// from an implementor. This interface is expected to be implemented outside of the monitor
// for the component which generates the event data for the registering monitor.
// The implementor must have a unique name which gets returned from `SenderName()`.
// The implementor is responsible for calling `Event()` on all monitors once they have
// registered through `Register()`.
type ReceiverRegistration interface {
	// SenderName must return a globally unique name of the implementor.
	SenderName() string

	// Register will register the given `monitor` for receiving events under `name`.
	// The registering monitor must implement `ReceiveEvents` before it can register.
	// Multiple calls to this function for the same `name` must update the internal
	// state of the implementor to now send events to the newly regitered monitor of this
	// name. Only one registration of a monitor of the same name is allowed.
	Register(name string, monitor ReceiveEvents) error
}
