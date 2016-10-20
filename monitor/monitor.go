package monitor

import (
	"github.com/aporeto-inc/trireme/eventlog"
	"github.com/aporeto-inc/trireme/interfaces"
)

// EventMonitor is the base of any Monitor. It holds the references to the policy objects.
type EventMonitor struct {
	PUHandler interfaces.ProcessingUnitsHandler
	// logger is the implementation of the remote logger
	Logger eventlog.EventLogger
}
