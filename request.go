package trireme

import "github.com/aporeto-inc/trireme/policy"

const (
	requestCreate  = 1
	requestDelete  = 2
	requestDestroy = 3
	policyUpdate   = 4
)

type triremeRequest struct {
	contextID   string
	reqType     int
	runtimeInfo *policy.PURuntime
	policyInfo  *policy.PUPolicy
	returnChan  chan error
}
