package registerer

import (
	"fmt"

	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/rpc/events"
	"github.com/aporeto-inc/trireme-lib/rpc/processor"
)

// registerer provides a way for others to register a registerer
type registerer struct {
	handlers map[constants.PUType]map[events.Event]events.EventHandler
}

// New returns a new registerer
func New() Registerer {

	return &registerer{
		handlers: map[constants.PUType]map[events.Event]events.EventHandler{},
	}
}

// RegisterProcessor registers an event processor for a given PUTYpe. Only one
// processor is allowed for a given PU Type.
func (r *registerer) RegisterProcessor(puType constants.PUType, ep processor.Processor) error {

	if _, ok := r.handlers[puType]; ok {
		return fmt.Errorf("Processor already registered for this PU type %d ", puType)
	}

	r.handlers[puType] = map[events.Event]events.EventHandler{}

	r.addHandler(puType, events.EventStart, ep.Start)
	r.addHandler(puType, events.EventStop, ep.Stop)
	r.addHandler(puType, events.EventCreate, ep.Create)
	r.addHandler(puType, events.EventDestroy, ep.Destroy)
	r.addHandler(puType, events.EventPause, ep.Pause)
	r.addHandler(puType, events.EventResync, ep.ReSync)

	return nil
}

func (r *registerer) GetHandler(puType constants.PUType, eventType events.Event) (events.EventHandler, error) {
	handlers, ok := r.handlers[puType]
	if !ok {
		return nil, fmt.Errorf("PUType %d not registered", puType)
	}

	e, ok := handlers[eventType]
	if !ok {
		return nil, fmt.Errorf("PUType %d event type %s not registered", puType, eventType)
	}

	return e, nil
}

// addHandler adds a handler for a puType/event.
func (r *registerer) addHandler(puType constants.PUType, event events.Event, handler events.EventHandler) {
	r.handlers[puType][event] = handler
}
