package enforcer

import (
	"fmt"
	"os"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer_adaptor"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/utils/tokens"
)

const (
	enforcer_starting = 0
	enforcer_running
	enforcer_stopped
)

type internal_enforcer_data struct {
	enforcer_state   uint8
	enforcer_context string
	monitoring_pid   int
}
type enforcer_client_data struct {
	managed_enforcers map[string]internal_enforcer_data
}

//Need to find the right place to do this patchup
func DockerFix(pid int) {

}
func (s *enforcer_client_data) Enforce(contextID string, puInfo *policy.PUInfo) error {
	//Launch the process
	/*Check if the enforcer already exists in that context

	 */
	_, ok := s.managed_enforcers[contextID]

	if ok {
		panic(fmt.Sprintf("Enforcer already exists in this context %s", contextID))
	}
	//DockerFix(puInfo.Pid())
	//Fixup needed here since docker does not create sufficient links
	args := []string{enforcer_adaptor.MsgPipe, contextID}
	attr := new(os.ProcAttr)
	process, err := os.StartProcess(enforcer_adaptor.Enforcer_bin, args, attr)
	if err != nil {
		//Log an error
		fmt.Println("Error Failed to launch Enforcer")
		return err
	} else {
		s.managed_enforcers[contextID] = internal_enforcer_data{enforcer_running, contextID, process.Pid}
	}
	//wait for process to initiate wait for some time
	//might want to use a separate unix socket to indicate
	//Init the RPC process

	//Call functions to
	return nil
}

func (s *enforcer_client_data) Unenforce(contextID string) error {
	return nil
}

func (s *enforcer_client_data) Start() error {
	//Enforcer is a new process
	//We don't know which context to launch this
	//The work we do here has to move to Enforce
	return nil
}

func (s *enforcer_client_data) Stop() error {
	return nil
}

func (s *enforcer_client_data) GetFilterQueue() *enforcer_adaptor.FilterQueue {
	return nil
}
func (s *enforcer_client_data) PublicKeyAdd(host string, cert []byte) error {
	return nil
}

func NewDefaultDataPathEnforcer(
	serverID string,
	collector collector.EventCollector,
	secrets tokens.Secrets,
) enforcer_adaptor.PolicyEnforcer {

	return new(enforcer_client_data)
}
