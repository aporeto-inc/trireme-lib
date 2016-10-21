package trireme

import "github.com/aporeto-inc/trireme/policy"

const (
	requestCreate = 1
	requestDelete = 2
	policyUpdate  = 3
)

type triremeRequest struct {
	contextID   string
	reqType     int
	runtimeInfo *policy.PURuntime
	policyInfo  *policy.PUPolicy
	returnChan  chan error
}
