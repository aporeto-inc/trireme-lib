package supervisor

import (
	"reflect"
	"testing"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor/iptablesutils"
	"github.com/aporeto-inc/trireme/supervisor/provider"
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
	ipt := provider.NewTestIptablesProvider()
	ipu := iptablesutils.NewIptableUtils(ipt)
	networks := []string{"0.0.0.0/0"}

	s, err := NewIPTablesSupervisor(c, pe, ipu, networks)
	if err != nil {
		t.Errorf("NewIPTables should not fail. Error received: %s", err)
		t.SkipNow()
	}
	if !reflect.DeepEqual(s.(*iptablesSupervisor).targetNetworks, networks) {
		t.Errorf("Networks after create not equal")
	}
	return s.(*iptablesSupervisor)
}

func TestNewIPTablesSupervisor(t *testing.T) {

	c := &collector.DefaultCollector{}
	pe := mockenforcerDefaultFQConfig(t)
	ipt := provider.NewTestIptablesProvider()
	ipu := iptablesutils.NewIptableUtils(ipt)
	networks := []string{"0.0.0.0/0"}

	// Test with normal parameters
	_, err := NewIPTablesSupervisor(c, pe, ipu, networks)
	if err != nil {
		t.Errorf("NewIPTables should not fail. Error received: %s", err)
	}
	// Test with Empty Collector
	_, err = NewIPTablesSupervisor(nil, pe, ipu, networks)
	if err == nil {
		t.Errorf("NewIPTables should fail because of empty Collector. No Error received.")
	}

	// Test with Empty Enforcer
	_, err = NewIPTablesSupervisor(c, nil, ipu, networks)
	if err == nil {
		t.Errorf("NewIPTables should fail because of empty Enforcer. No Error received.")
	}

	// Test with Empty Utils
	_, err = NewIPTablesSupervisor(c, pe, nil, networks)
	if err == nil {
		t.Errorf("NewIPTables should fail because of empty IPTables Utils. No Error received.")
	}

	// Test with Empty Networks
	_, err = NewIPTablesSupervisor(c, pe, ipu, nil)
	if err == nil {
		t.Errorf("NewIPTables should fail because of empty TriremeNetworks. No Error received.")
	}
}

func TestIPTablesSuperviseErrorEmptyContainerInfo(t *testing.T) {
	s := doNewIPTSupervisor(t)

	// Test empty ContainerInfo
	err := s.Supervise("123", nil)
	if err == nil {
		t.Errorf("Empty containerInfo should result in Error")
	}
}

func TestIPTablesSuperviseErrorNoIPParams(t *testing.T) {
	s := doNewIPTSupervisor(t)

	containerInfo := policy.NewPUInfo("1234567")
	// Test no IP parameters. Create case
	err := s.Supervise("1234567", containerInfo)
	if err == nil {
		t.Errorf("No Error even though IP not part of Policy")
	}
}

func TestIPTablesSuperviseCreateAndUpdate(t *testing.T) {
	s := doNewIPTSupervisor(t)

	containerInfo := policy.NewPUInfo("12345")
	containerInfo.Runtime.SetIPAddresses(map[string]string{"bridge": "30.30.30.30"})
	containerInfo.Policy.PolicyIPs = []string{"30.30.30.30"}

	// Test expected parameters. Create case
	err := s.Supervise("12345", containerInfo)
	if err != nil {
		t.Errorf("Got error on create %s", err)
	}

	// Test expected parameters. Update case
	err = s.Supervise("12345", containerInfo)
	if err != nil {
		t.Errorf("Got error on Update %s", err)
	}
}

func TestIPTablesUnsuperviseErrorNonExistingContainer(t *testing.T) {
	s := doNewIPTSupervisor(t)

	// Test Unsupervise for nonexistingContainer. Should return an error
	err := s.Unsupervise("123")
	if err == nil {
		t.Errorf("Empty containerInfo should result in Error")
	}
}

func TestIPTablesUnsuperviseExistingContainer(t *testing.T) {
	s := doNewIPTSupervisor(t)

	containerInfo := policy.NewPUInfo("12345")
	containerInfo.Runtime.SetIPAddresses(map[string]string{"bridge": "30.30.30.30"})
	containerInfo.Policy.PolicyIPs = []string{"30.30.30.30"}

	// Test expected parameters. Create case
	err := s.Supervise("12345", containerInfo)
	if err != nil {
		t.Errorf("Got error on create %s", err)
	}

	// Test Unsupervise for existingContainer. Should not return an error
	err = s.Unsupervise("12345")
	if err != nil {
		t.Errorf("Unsupervise of existing container should not result in error: %s", err)
	}

	// Test Unsupervise for nonexistingContainer. Should return an error
	err = s.Unsupervise("12345")
	if err == nil {
		t.Errorf("Unsupervise of existing container should  result in an error")
	}
}

func TestIPTablesStart(t *testing.T) {
	s := doNewIPTSupervisor(t)
	err := s.Start()
	if err != nil {
		t.Errorf("Start should not return an errir: %s", err)
	}
}

func TestIPTablesStop(t *testing.T) {
	s := doNewIPTSupervisor(t)
	s.Start()
	err := s.Stop()
	if err != nil {
		t.Errorf("Stop should not return an errir: %s", err)
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
func TestAddContainerChain(t *testing.T) {
	/*
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

		//Setup expectations

		err := s.Supervise("12345", containerInfo)
		if err == nil {
			t.Errorf("ignored Error from add ContainerChain raw::  %s", err)
			t.SkipNow()
		}

		// Setup expectations
		err = s.Supervise("12345", containerInfo)
		if err == nil {
			t.Errorf("ignored Error from add app specific ContainerChain")
			t.SkipNow()
		}

		// Setup expectations
		err = s.Supervise("12345", containerInfo)
		if err == nil {
			t.Errorf("ignored Error from add net specific ContainerChain")
			t.SkipNow()
		}

		// Setup expectations
		err = s.Supervise("12345", containerInfo)
		if err != nil {
			t.Errorf("Supervise failed %s", err)
			t.SkipNow()
		}

		// Setup expectations
		s.Unsupervise("12345")
	*/
}

func TestAddChainRules(t *testing.T) {
	/*
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
		m := s.ipt.(provider.TestIptablesProvider)

		const (
			testPoint = iota
			testPoint1
			testPoint2
			testPoint3
			testPoint4
		)
		testPoints := testPoint1
		targetPoint := testPoint1
		//Check if there are now rules anymore
		m.MockAppend(t, func(table, chain string, rulespec ...string) error {

			if testPoints == targetPoint {
				return errors.New("Failed to append")
			}
			testPoints++
			return nil

		})
		err := s.Supervise("12345", containerInfo)
		if err == nil {
			t.Errorf("ignored Error from Append")
			t.SkipNow()
		}

		//Sucess Case
		testPoints = testPoint1
		targetPoint = 0
		err = s.Supervise("12345", containerInfo)
		if err != nil {
			t.Errorf("Supervise failed %s", err)
			t.SkipNow()
		}
		s.Unsupervise("12345")
	*/
}

func TestAddPacketTrap(t *testing.T) {
	/*
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
		m := s.ipt.(provider.TestIptablesProvider)
		const (
			testPoint  = 0
			testPoint1 = 3
			testPoint2
			testPoint3
			testPoint4
		)
		testPoints := testPoint
		targetPoint := testPoint1
		//Check if there are now rules anymore
		m.MockAppend(t, func(table, chain string, rulespec ...string) error {
			if testPoints == targetPoint {
				return errors.New("Failed to append")
			}
			testPoints++
			return nil

		})
		err := s.Supervise("12345", containerInfo)
		if err == nil {
			t.Errorf("ignored Error from Append")
			//debug.PrintStack()
			t.SkipNow()
		}

		//Sucess Case
		testPoints = testPoint1
		targetPoint = testPoint
		err = s.Supervise("12345", containerInfo)
		if err != nil {
			t.Errorf("Supervise failed %s", err)
			t.SkipNow()
		}
		s.Unsupervise("12345")
	*/
}

func TestAddAppACLs(t *testing.T) {
	/*
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
		m := s.ipt.(provider.TestIptablesProvider)
		//25 is derived from the addchainrules+AddPacketTrap calling append
		//We don't want append to fail in addchainrules
		const (
			testPoint  = 25
			testPoint0 = 0
			testPoint1 = 7
			testPoint2 = 15
			testPoint3
			testPoint4
		)
		testPoints := testPoint0
		targetPoint := testPoint1
		//Check if there are now rules anymore

		m.MockAppend(t, func(table, chain string, rulespec ...string) error {
			if testPoints == targetPoint {
				testPoints++
				return errors.New("Failed to append")
			}
			testPoints++
			return nil

		})
		err := s.Supervise("12345", containerInfo)
		if err == nil {
			t.Errorf("ignored Error from Append")
			//debug.PrintStack()
			t.SkipNow()
		}

		//Second if condition
		testPoints = testPoint1
		targetPoint = testPoint3
		err = s.Supervise("12345", containerInfo)
		if err == nil {
			t.Errorf("ignored Error from Append")
			//debug.PrintStack()
			t.SkipNow()
		}
		//Success Case
		testPoints = testPoint1
		targetPoint = testPoint0
		err = s.Supervise("12345", containerInfo)
		if err != nil {
			t.Errorf("Supervise failed %s", err)
			t.SkipNow()
		}
		s.Unsupervise("12345")
	*/
}

func TestAddNetACLs(t *testing.T) {
	/*
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
		m := s.ipt.(provider.TestIptablesProvider)
		//25 is derived from the addchainrules+AddPacketTrap calling append
		//We don't want append to fail in addchainrules
		const (
			testPoint  = 0
			testPoint0 = 0
			testPoint1 = 8
			testPoint2 = 9
			testPoint3
			testPoint4
		)
		testPoints := testPoint0
		targetPoint := testPoint1
		//Check if there are now rules anymore

		m.MockAppend(t, func(table, chain string, rulespec ...string) error {

			if testPoints == targetPoint {
				testPoints++
				return errors.New("Failed to append")
			}
			testPoints++
			return nil

		})
		err := s.Supervise("12345", containerInfo)
		if err == nil {
			t.Errorf("ignored Error from Append expected:%v actual:%v", targetPoint, testPoints)
			//debug.PrintStack()
			t.SkipNow()
		}

		//Second Append for default rule
		testPoints = testPoint0
		targetPoint = testPoint2
		err = s.Supervise("12345", containerInfo)
		if err == nil {
			t.Errorf("ignored Error from Append expected:%v actual:%v", targetPoint, testPoints)
			//debug.PrintStack()
			t.SkipNow()
		}
		//Sucess Case
		testPoints = testPoint1
		targetPoint = testPoint0
		err = s.Supervise("12345", containerInfo)
		if err != nil {
			t.Errorf("Error in Supervise expected:%v actual:%v", targetPoint, testPoints)
			//debug.PrintStack()
			t.SkipNow()
		}
		s.Unsupervise("12345")
	*/
}

func TestDeleteChainRules(t *testing.T) {
	/*
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
		m := s.ipt.(provider.TestIptablesProvider)
		//25 is derived from the addchainrules+AddPacketTrap calling append
		//We don't want append to fail in addchainrules
		const (
			testPoint  = 0
			testPoint0 = 0
			testPoint1 = 1
			testPoint2
			testPoint3
			testPoint4
		)

		err := s.Supervise("12345", containerInfo)
		//Call Supervise again with the same context id
		//Will force a doUpDatePU
		containerInfo1 := policy.NewPUInfo("12345")
		containerInfo1.Policy.IngressACLs = []policy.IPRule{policy.IPRule{
			Address:  "10.10.0.0/16",
			Port:     "80",
			Protocol: "tcp",
		}}

		containerInfo1.Policy.EgressACLs = []policy.IPRule{policy.IPRule{
			Address:  "10.20.0.0/16",
			Port:     "80",
			Protocol: "tcp",
		}}
		containerInfo1.Runtime.SetIPAddresses(map[string]string{"bridge": "15.30.30.30"})
		containerInfo1.Policy.PolicyIPs = []string{"15.30.30.30"}
		testPoints := testPoint0
		targetPoint := testPoint1
		m.MockDelete(t, func(table, chain string, rulespec ...string) error {
			if testPoints == targetPoint {
				testPoints++
				return errors.New("Failed to append")
			}
			testPoints++
			return nil

		})

		err = s.Supervise("12345", containerInfo1)
		if err == nil {
			t.Errorf("ignored delete error")
		}

		//Sucess case now
		testPoints = testPoint1
		targetPoint = testPoint0
		err = s.Supervise("12345", containerInfo)
		if err != nil {
			t.Errorf("Error during Supervise")
		}
		//Trigger and doUpdatePU
		err = s.Supervise("12345", containerInfo1)
		if err != nil {
			t.Errorf("Update of container failed")
		}
	*/
}

func TestExcludedIP(t *testing.T) {
	/*
		supervisor := doNewIPTSupervisor(t)
		ipt := supervisor.ipt.(provider.TestIptablesProvider)

		// Testing normal Workflow:Add and Remove 10.0.0.1/32

		excludedIP := "10.0.0.1/32"
		indexInsert := 0
		ipt.MockInsert(t, func(table, chain string, pos int, rulespec ...string) error {
			fmt.Println(table)
			switch indexInsert {
			case 0:
				// First Iteration
				expectedTable := "raw"
				expectedChain := "PREROUTING"
				expectedPos := 1
				expectedRuleSpec := []string{"-d", excludedIP, "-m", "comment", "--comment", "Trireme excluded IP", "-j", "ACCEPT"}
				if table != expectedTable {
					t.Errorf("Was expecting Table to be %s , got %s", expectedTable, table)
				}
				if chain != expectedChain {
					t.Errorf("Was expecting Chain to be %s , got %s", expectedChain, chain)

				}
				if pos != expectedPos {
					t.Errorf("Was expecting Position to be %d , got %d", expectedPos, pos)
				}
				if !reflect.DeepEqual(rulespec, expectedRuleSpec) {
					t.Errorf("Was expecting Rulespec to be %+v , got %+v", expectedRuleSpec, rulespec)
				}

			case 1:
				// First Iteration
				expectedTable := "mangle"
				expectedChain := "PREROUTING"
				expectedPos := 1
				expectedRuleSpec := []string{"-d", excludedIP, "-p", "tcp", "-m", "comment", "--comment", "Trireme excluded IP", "-j", "ACCEPT"}
				if table != expectedTable {
					t.Errorf("Was expecting Table to be %s , got %s", expectedTable, table)
				}
				if chain != expectedChain {
					t.Errorf("Was expecting Chain to be %s , got %s", expectedChain, chain)

				}
				if pos != expectedPos {
					t.Errorf("Was expecting Position to be %d , got %d", expectedPos, pos)
				}
				if !reflect.DeepEqual(rulespec, expectedRuleSpec) {
					t.Errorf("Was expecting Rulespec to be %+v , got %+v", expectedRuleSpec, rulespec)
				}

			case 2:
				// First Iteration
				expectedTable := "mangle"
				expectedChain := "POSTROUTING"
				expectedPos := 1
				expectedRuleSpec := []string{"-s", excludedIP, "-m", "comment", "--comment", "Trireme excluded IP", "-j", "ACCEPT"}
				if table != expectedTable {
					t.Errorf("Was expecting Table to be %s , got %s", expectedTable, table)
				}
				if chain != expectedChain {
					t.Errorf("Was expecting Chain to be %s , got %s", expectedChain, chain)

				}
				if pos != expectedPos {
					t.Errorf("Was expecting Position to be %d , got %d", expectedPos, pos)
				}
				if !reflect.DeepEqual(rulespec, expectedRuleSpec) {
					t.Errorf("Was expecting Rulespec to be %+v , got %+v", expectedRuleSpec, rulespec)
				}

			}
			indexInsert++
			return nil
		})
		indexDelete := 0

		ipt.MockDelete(t, func(table, chain string, rulespec ...string) error {
			fmt.Println(table)
			switch indexDelete {
			case 0:
				// First Iteration
				expectedTable := "raw"
				expectedChain := "PREROUTING"
				expectedRuleSpec := []string{"-d", excludedIP, "-m", "comment", "--comment", "Trireme excluded IP", "-j", "ACCEPT"}
				if table != expectedTable {
					t.Errorf("Was expecting Table to be %s , got %s", expectedTable, table)
				}
				if chain != expectedChain {
					t.Errorf("Was expecting Chain to be %s , got %s", expectedChain, chain)

				}
				if !reflect.DeepEqual(rulespec, expectedRuleSpec) {
					t.Errorf("Was expecting Rulespec to be %+v , got %+v", expectedRuleSpec, rulespec)
				}

			case 1:
				// First Iteration
				expectedTable := "mangle"
				expectedChain := "PREROUTING"
				expectedRuleSpec := []string{"-d", excludedIP, "-p", "tcp", "-m", "comment", "--comment", "Trireme excluded IP", "-j", "ACCEPT"}
				if table != expectedTable {
					t.Errorf("Was expecting Table to be %s , got %s", expectedTable, table)
				}
				if chain != expectedChain {
					t.Errorf("Was expecting Chain to be %s , got %s", expectedChain, chain)

				}
				if !reflect.DeepEqual(rulespec, expectedRuleSpec) {
					t.Errorf("Was expecting Rulespec to be %+v , got %+v", expectedRuleSpec, rulespec)
				}

			case 2:
				// First Iteration
				expectedTable := "mangle"
				expectedChain := "POSTROUTING"
				expectedRuleSpec := []string{"-s", excludedIP, "-m", "comment", "--comment", "Trireme excluded IP", "-j", "ACCEPT"}
				if table != expectedTable {
					t.Errorf("Was expecting Table to be %s , got %s", expectedTable, table)
				}
				if chain != expectedChain {
					t.Errorf("Was expecting Chain to be %s , got %s", expectedChain, chain)

				}
				if !reflect.DeepEqual(rulespec, expectedRuleSpec) {
					t.Errorf("Was expecting Rulespec to be %+v , got %+v", expectedRuleSpec, rulespec)
				}
			}
			indexDelete++
			return nil
		})

		err := supervisor.AddExcludedIP(excludedIP)
		if err != nil {
			t.Errorf("Was expecting nil error return, got %s", err)
		}
		err = supervisor.RemoveExcludedIP(excludedIP)
		if err != nil {
			t.Errorf("Was expecting nil error return, got %s", err)
		}

		// ErrorReturn Tests:
		excludedIP = "20.0.0.1/32"
		ipt.MockInsert(t, func(table, chain string, pos int, rulespec ...string) error {
			return fmt.Errorf("IPTable Error ")
		})
		ipt.MockDelete(t, func(table, chain string, rulespec ...string) error {
			return fmt.Errorf("IPTable Error ")
		})

		// Testing Error on Adding
		err = supervisor.AddExcludedIP(excludedIP)
		if err == nil {
			t.Errorf("Was expecting error return, got nil")
		}

		// Testing error on Removing
		err = supervisor.RemoveExcludedIP(excludedIP)
		if err == nil {
			t.Errorf("Was expecting error return, got nil")
		}
	*/
}
