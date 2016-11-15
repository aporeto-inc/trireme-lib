package trireme

import (
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/policy"
)

const (
	handleEvent  = 1
	policyUpdate = 2
)

type triremeRequest struct {
	contextID  string
	reqType    int
	eventType  monitor.Event
	policyInfo *policy.PUPolicy
	returnChan chan error
}
