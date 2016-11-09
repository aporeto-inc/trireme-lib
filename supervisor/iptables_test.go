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
	const (
		test_point int =iota
		test_point_1 =1
		test_point_2 =2
		test_point_3 =3 
		test_point_4 = 4
	)
	containerInfo.Runtime.SetIPAddresses(map[string]string{"bridge": "30.30.30.30"})
	containerInfo.Policy.PolicyIPs = []string{"30.30.30.30"}
	m := s.ipt.(TestIptablesProvider)
	test_points := test_point_1
	target_point := test_point_1
	m.MockNewChain(t,func(table,chain string)(error){
		
		if test_points==target_point {
			return errors.New("Failed to create raw table")
		}else{
			test_points++
			return nil
		}
		
		return nil
	})
	err := s.Supervise("12345",containerInfo)
	if(err == nil){
		t.Errorf("ignored Error from add ContainerChain raw::  %s",err)
		t.SkipNow()
	}
		
	test_points = test_point_1
	target_point = test_point_2
	err = s.Supervise("12345",containerInfo)
	
	if(err == nil){
		t.Errorf("ignored Error from add app specific ContainerChain")
		t.SkipNow()
	}
	test_points = test_point_1
	target_point = test_point_3
	err = s.Supervise("12345",containerInfo)
	if(err == nil){
		t.Errorf("ignored Error from add net specific ContainerChain")
		t.SkipNow()
	}
	
	test_points = test_point_1
	target_point = test_point_4
	err = s.Supervise("12345",containerInfo)
	if(err != nil){
		t.Errorf("Supervise failed %s",err)
		t.SkipNow()
	}
	err = s.Unsupervise("12345")
	
	
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
	
	const (
		test_point int =iota
		test_point_1
		test_point_2
		test_point_3
		test_point_4
	)
	test_points := test_point_1
	target_point := test_point_1
	//Check if there are now rules anymore
	m.MockAppend(t,func(table,chain string,rulespec ...string)(error){
		
		if test_points==target_point {
			return errors.New("Failed to append")
		}else{
			test_points++
			return nil
		}
		
		return nil
	})
	err := s.Supervise("12345",containerInfo)
	if(err == nil){
		t.Errorf("ignored Error from Append")
		t.SkipNow()
	}

	//Sucess Case
	test_points = test_point_1
	target_point = 0
	err = s.Supervise("12345",containerInfo)
	if(err != nil){
		t.Errorf("Supervise failed %s",err)
		t.SkipNow()
	}
	err = s.Unsupervise("12345")
}

func TestAddPacketTrap(t *testing.T){
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
	const (
		test_point int =0
		test_point_1 = 3
		test_point_2
		test_point_3
		test_point_4
	)
	test_points := test_point
	target_point := test_point_1
	//Check if there are now rules anymore
	m.MockAppend(t,func(table,chain string,rulespec ...string)(error){
		if test_points==target_point {
			return errors.New("Failed to append")
		}else{
			test_points++
			return nil
		}
		
		return nil
	})
	err := s.Supervise("12345",containerInfo)
	if(err == nil){
		t.Errorf("ignored Error from Append")
		//debug.PrintStack()
		t.SkipNow()
	}

	//Sucess Case
	test_points = test_point_1
	target_point = test_point
	err = s.Supervise("12345",containerInfo)
	if(err != nil){
		t.Errorf("Supervise failed %s",err)
		t.SkipNow()
	}
	err = s.Unsupervise("12345")
	
}

func TestAddAppACLs(t *testing.T){
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
	//25 is derived from the addchainrules+addPacketTrap calling append
	//We don't want append to fail in addchainrules 
	const (
		test_point int =25
		test_point_0 =0
		test_point_1 = 7
		test_point_2 = 15
		test_point_3
		test_point_4
	)
	test_points := test_point_0
	target_point := test_point_1
	//Check if there are now rules anymore

	m.MockAppend(t,func(table,chain string,rulespec ...string)(error){
		if test_points==target_point {
			test_points++
			return errors.New("Failed to append")
		}else{
			test_points++
			return nil
		}
		
		return nil
	})
	err := s.Supervise("12345",containerInfo)
	if(err == nil){
		t.Errorf("ignored Error from Append")
		//debug.PrintStack()
		t.SkipNow()
	}

	//Second if condition 
	test_points = test_point_1
	target_point = test_point_3
	err = s.Supervise("12345",containerInfo)
	if(err == nil){
		t.Errorf("ignored Error from Append")
		//debug.PrintStack()
		t.SkipNow()
	}
	//Success Case
	test_points = test_point_1
	target_point = test_point_0
	err = s.Supervise("12345",containerInfo)
	if(err != nil){
		t.Errorf("Supervise failed %s",err)
		t.SkipNow()
	}
	err = s.Unsupervise("12345")

}

func TestAddNetACLs(t *testing.T){
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
	//25 is derived from the addchainrules+addPacketTrap calling append
	//We don't want append to fail in addchainrules 
	const (
		test_point int=0
		test_point_0 =0
		test_point_1 = 9
		test_point_2 = 10
		test_point_3
		test_point_4
	)
	test_points := test_point_0
	target_point := test_point_1
	//Check if there are now rules anymore

	m.MockAppend(t,func(table,chain string,rulespec ...string)(error){

		if test_points==target_point {
			test_points++
			return errors.New("Failed to append")
		}else{
			test_points++
			return nil
		}
		
		return nil
	})
	err := s.Supervise("12345",containerInfo)
	if(err == nil){
		t.Errorf("ignored Error from Append")
		//debug.PrintStack()
		t.SkipNow()
	}

	//Second Append for default rule
	test_points = test_point_0
	target_point = test_point_2
	err = s.Supervise("12345",containerInfo)
	if(err == nil){
		t.Errorf("ignored Error from Append")
		//debug.PrintStack()
		t.SkipNow()
	}
	//Sucess Case
	test_points = test_point_1
	target_point = test_point_0
	err = s.Supervise("12345",containerInfo)
	if(err != nil){
		t.Errorf("Error in Supervise")
		//debug.PrintStack()
		t.SkipNow()
	}
	err = s.Unsupervise("12345")
}

func TestDeleteChainRules(t *testing.T){
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
	//25 is derived from the addchainrules+addPacketTrap calling append
	//We don't want append to fail in addchainrules 
	const (
		test_point int=0
		test_point_0 =0
		test_point_1 = 1
		test_point_2
		test_point_3
		test_point_4
	)
	
	err := s.Supervise("12345",containerInfo)
	//Call Supervise again with the same context id
	//Will force a doUpDatePU
	containerInfo_1 := policy.NewPUInfo("12345")
	containerInfo_1.Policy.IngressACLs = []policy.IPRule{policy.IPRule{
		Address:  "10.10.0.0/16",
		Port:     "80",
		Protocol: "tcp",
	}}

	containerInfo_1.Policy.EgressACLs = []policy.IPRule{policy.IPRule{
		Address:  "10.20.0.0/16",
		Port:     "80",
		Protocol: "tcp",
	}}
	containerInfo_1.Runtime.SetIPAddresses(map[string]string{"bridge": "15.30.30.30"})
	containerInfo_1.Policy.PolicyIPs = []string{"15.30.30.30"}
	test_points := test_point_0
	target_point := test_point_1
	m.MockDelete(t,func(table,chain string,rulespec ...string)(error){
		if test_points==target_point {
			test_points++
			return errors.New("Failed to append")
		}else{
			test_points++
			return nil
		}
	})

	err = s.Supervise("12345",containerInfo_1)
	if(err == nil){
		t.Errorf("ignored delete error")
	}

	//Sucess case now
	test_points = test_point_1
	target_point = test_point_0
	err = s.Supervise("12345",containerInfo)
	if(err != nil){
		t.Errorf("Error during Supervise")
	}
	//Trigger and doUpdatePU
	err = s.Supervise("12345",containerInfo_1)
	if(err != nil){
		t.Errorf("Update of container failed")
	}
}
