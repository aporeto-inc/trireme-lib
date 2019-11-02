package registerer

import (
	"go.aporeto.io/trireme-lib/v11/common"
	"go.aporeto.io/trireme-lib/v11/monitor/processor"
)

// Registerer inteface allows event processors to register themselves with the event server.
type Registerer interface {

	// Register Processor registers event processors for a certain type of PU
	RegisterProcessor(puType common.PUType, p processor.Processor) error

	GetHandler(puType common.PUType, e common.Event) (common.EventHandler, error)
}
