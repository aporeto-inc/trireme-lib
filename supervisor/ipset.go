package supervisor

import "github.com/aporeto-inc/trireme/policy"

type ipsetSupervisor struct {
}

// NewIPSetSupervisor returns a new implementation of the Supervisor based on IPSets.
func NewIPSetSupervisor() (Supervisor, error) {
	return &ipsetSupervisor{}, nil
}

func (s *ipsetSupervisor) Supervise(contextID string, containerInfo *policy.PUInfo) error {
	return nil
}

func (s *ipsetSupervisor) Unsupervise(contextID string) error {
	return nil
}

func (s *ipsetSupervisor) Start() error {
	return nil
}

func (s *ipsetSupervisor) Stop() error {
	return nil
}
