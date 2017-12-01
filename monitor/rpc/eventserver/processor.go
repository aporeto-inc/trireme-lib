package eventserver

import (
	"fmt"

	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/monitor"
)

// processor provides a way for others to register a processor
type processor struct {
	handlers map[constants.PUType]map[monitor.Event]EventHandler
}

// RegisterProcessor registers an event processor for a given PUTYpe. Only one
// processor is allowed for a given PU Type.
func (p *processor) RegisterProcessor(puType constants.PUType, ep processor.EventProcessor) error {

	if _, ok := p.handlers[puType]; ok {
		return fmt.Errorf("Processor already registered for this PU type %d ", puType)
	}

	p.handlers[puType] = map[monitor.Event]EventHandler{}

	p.addHandler(puType, monitor.EventStart, ep.Start)
	p.addHandler(puType, monitor.EventStop, ep.Stop)
	p.addHandler(puType, monitor.EventCreate, ep.Create)
	p.addHandler(puType, monitor.EventDestroy, ep.Destroy)
	p.addHandler(puType, monitor.EventPause, ep.Pause)
	p.addHandler(puType, monitor.EventResync, ep.ReSync)

	return nil
}
