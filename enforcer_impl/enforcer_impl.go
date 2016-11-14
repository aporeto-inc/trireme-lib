package enforcer_impl

import (
	"github.com/aporeto-inc/trireme/enforcer_adaptor"
	"github.com/aporeto-inc/trireme/policy"
)

type enforcer_conf struct {
	contextID    string
	comm_channel string
}
type enforcer struct {
	config enforcer_conf
}

var active_enforcers = map[string]*enforcer{}

func (s *enforcer) Enforce(contextID string, puInfo *policy.PUInfo) error {

	return nil
}

func (s *enforcer) Unenforce(contextID string) error {
	return nil
}

func (s *enforcer) Start() error {

	return nil
}

func (s *enforcer) Stop() error {
	return nil
}

func (s *enforcer) GetFilterQueue() *enforcer_adaptor.FilterQueue {
	return nil

}

func NewEnforcer(contextID string, unix_sock_path string) enforcer_adaptor.PolicyEnforcer {
	a := &enforcer{config: enforcer_conf{contextID: contextID, comm_channel: unix_sock_path}}
	active_enforcers[contextID] = a
	return a
}
func (s *enforcer) PublicKeyAdd(host string, cert []byte) error {
	return nil
}
