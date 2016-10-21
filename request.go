package trireme

import "github.com/aporeto-inc/trireme/policy"

const requestCreate = 1
const requestDelete = 2
const policyUpdate = 3

type triremeRequest struct {
	contextID   string
	reqType     int
	runtimeInfo *policy.PURuntime
	policyInfo  *policy.PUPolicy
	returnChan  chan error
}
