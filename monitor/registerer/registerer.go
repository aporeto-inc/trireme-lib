package registerer

import (
	"fmt"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/processor"
)

// registerer provides a way for others to register a registerer
type registerer struct {
	handlers map[common.PUType]map[common.Event]common.EventHandler
}

// New returns a new registerer
func New() Registerer {

	return &registerer{
		handlers: map[common.PUType]map[common.Event]common.EventHandler{},
	}
}

// RegisterProcessor registers an event processor for a given PUTYpe. Only one
// processor is allowed for a given PU Type.
func (r *registerer) RegisterProcessor(puType common.PUType, ep processor.Processor) error {

	if _, ok := r.handlers[puType]; ok {
		return fmt.Errorf("Processor already registered for this PU type %d ", puType)
	}

	r.handlers[puType] = map[common.Event]common.EventHandler{}

	r.addHandler(puType, common.EventStart, ep.Start)
	r.addHandler(puType, common.EventStop, ep.Stop)
	r.addHandler(puType, common.EventCreate, ep.Create)
	r.addHandler(puType, common.EventDestroy, ep.Destroy)
	r.addHandler(puType, common.EventPause, ep.Pause)
	r.addHandler(puType, common.EventResync, ep.Resync)

	return nil
}

func (r *registerer) GetHandler(puType common.PUType, eventType common.Event) (common.EventHandler, error) {

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
func (r *registerer) addHandler(puType common.PUType, event common.Event, handler common.EventHandler) {
	r.handlers[puType][event] = handler
}
