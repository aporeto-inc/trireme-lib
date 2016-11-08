package supervisor

import (
	"reflect"
	"testing"
	"errors"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/policy"
	// "github.com/aporeto-inc/trireme/policy"
)

func mockenforcerDefaultFQConfig(t *testing.T) enforcer.PolicyEnforcer {
	pe := enforcer.NewTestPolicyEnforcer()
	pe.MockGetFilterQueue(t, func() *enforcer.FilterQueue {
		return &enforcer.FilterQueue{
			NetworkQueue:              enforcer.DefaultNetworkQueue,
			NetworkQueueSize:          enforcer.DefaultQueueSize,
			NumberOfNetworkQueues:     enforcer.DefaultNumberOfQueues,
			ApplicationQueue:          enforcer.DefaultApplicationQueue,
			ApplicationQueueSize:      enforcer.DefaultQueueSize,
			NumberOfApplicationQueues: enforcer.DefaultNumberOfQueues,
		}
	})
	return pe
}

func doNewIPTSupervisor(t *testing.T) *iptablesSupervisor {
	c := &collector.DefaultCollector{}
	pe := mockenforcerDefaultFQConfig(t)
	ipt := NewTestIptablesProvider()
	networks := []string{"0.0.0.0/0"}

	s, err := NewIPTablesSupervisor(c, pe, ipt, networks)
	if err != nil {
		t.Errorf("NewIPTables should not fail. Error received: %s", err)
		t.SkipNow()
	}
	if !reflect.DeepEqual(s.(*iptablesSupervisor).targetNetworks, networks) {
		t.Errorf("Networks after create not equal")
	}
	return s.(*iptablesSupervisor)
}

func TestNewIPTables(t *testing.T) {

	doNewIPTSupervisor(t)

}

//Invalid IP is checked in the caller 
func TestSupervise(t *testing.T) {

	s := doNewIPTSupervisor(t)
	containerInfo := policy.NewPUInfo("12345")
	containerInfo.Runtime.SetIPAddresses(map[string]string{"bridge": "30.30.30.30"})
	containerInfo.Policy.PolicyIPs = []string{"30.30.30.30"}

	err := s.Supervise("12345", containerInfo)
	if err != nil {
		t.Errorf("Got error %s", err)
	}

	err = s.Supervise("12345", containerInfo)
	if err != nil {
		t.Errorf("Got error %s", err)
	}

	err = s.Unsupervise("12345")
	if err != nil {
		t.Errorf("Got error %s", err)
	}
	
}

func TestSuperviseACLs(t *testing.T) {

	s := doNewIPTSupervisor(t)
	containerInfo := policy.NewPUInfo("12345")
	containerInfo.Policy.IngressACLs = []policy.IPRule{policy.IPRule{
		Address:  "20.20.0.0/16",
		Port:     "80",
		Protocol: "tcp",
	}}

	containerInfo.Policy.EgressACLs = []policy.IPRule{policy.IPRule{
		Address:  "20.20.0.0/16",
		Port:     "80",
		Protocol: "tcp",
	}}
	containerInfo.Runtime.SetIPAddresses(map[string]string{"bridge": "30.30.30.30"})
	containerInfo.Policy.PolicyIPs = []string{"30.30.30.30"}

	err := s.Supervise("12345", containerInfo)
	if err != nil {
		t.Errorf("Got error %s", err)
	}

	err = s.Supervise("12345", containerInfo)
	if err != nil {
		t.Errorf("Got error %s", err)
	}

	err = s.Unsupervise("12345")
	if err != nil {
		t.Errorf("Got error %s", err)
	}

}


//Call Supervise and we will mock AddContainer Chain here  by changing the mock defintions of newChain
//The function should cleanup on all errors 
func TestAddContainerChain(t *testing.T){
	s := doNewIPTSupervisor(t)
	containerInfo := policy.NewPUInfo("12345")
	containerInfo.Policy.IngressACLs = []policy.IPRule{policy.IPRule{
		Address:  "20.20.0.0/16",
		Port:     "80",
		Protocol: "tcp",
	}}

	containerInfo.Policy.EgressACLs = []policy.IPRule{policy.IPRule{
		Address:  "20.20.0.0/16",
		Port:     "80",
		Protocol: "tcp",
	}}
	containerInfo.Runtime.SetIPAddresses(map[string]string{"bridge": "30.30.30.30"})
	containerInfo.Policy.PolicyIPs = []string{"30.30.30.30"}
	m := s.ipt.(TestIptablesProvider)

	m.MockNewChain(t,func(table,chain string)(error){
		if(table == "raw" ){
			return errors.New("Failed to create raw table")
		}
		return nil
	})
	err := s.Supervise("12345",containerInfo)
	if(err == nil){
		t.Errorf("ignored Error from add ContainerChain:raw")
		t.SkipNow()
	}
	//Check if there are now rules anymore
	rules,err := m.ListChains("12345")
	if( len(rules) != 0 ){
		t.Errorf("State was not cleared after error")
	}

	
	m.MockNewChain(t,func(table,chain string)(error){
		if(table == "mangle"){
			return errors.New("Failed to create raw table")
		}
		return nil
	})
	err = s.Supervise("12345",containerInfo)
	
	if(err == nil){
		t.Errorf("ignored Error from addContainerChain:mangle")
		t.SkipNow()
	}
	//Check if there are now rules anymore
	rules,err = m.ListChains("12345")
	if( len(rules) != 0 ){
		t.Errorf("State was not cleared after error")
	}
}


func TestAddChainRules(t *testing.T){
	s := doNewIPTSupervisor(t)
	containerInfo := policy.NewPUInfo("12345")
	containerInfo.Policy.IngressACLs = []policy.IPRule{policy.IPRule{
		Address:  "20.20.0.0/16",
		Port:     "80",
		Protocol: "tcp",
	}}

	containerInfo.Policy.EgressACLs = []policy.IPRule{policy.IPRule{
		Address:  "20.20.0.0/16",
		Port:     "80",
		Protocol: "tcp",
	}}
	containerInfo.Runtime.SetIPAddresses(map[string]string{"bridge": "30.30.30.30"})
	containerInfo.Policy.PolicyIPs = []string{"30.30.30.30"}
	m := s.ipt.(TestIptablesProvider)
	

	m.MockAppend(t,func(table,chain string,rulespec ...string)(error){
		if(table == "raw" && chain == "PREROUTING"){
			return errors.New("Append Failed")
		}
		return nil
	})
	err := s.Supervise("12345",containerInfo)
	if(err == nil){
		t.Errorf("ignored Error from Append")
		t.SkipNow()
	}
	//Check if there are now rules anymore
	rules,err := m.ListChains("12345")
	if( len(rules) != 0 ){
		t.Errorf("State was not cleared after error")
	}
	
	
	
}


