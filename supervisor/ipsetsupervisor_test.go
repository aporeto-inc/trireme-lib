package supervisor

import (
	"testing"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor/provider"
)

func doNewIPSetSupervisor(t *testing.T) *ipsetSupervisor {
	c := &collector.DefaultCollector{}
	pe := mockenforcerDefaultFQConfig(t)
	ipt := provider.NewTestIptablesProvider()
	ips := provider.NewTestIpsetProvider()
	networks := []string{"0.0.0.0/0"}

	s, err := NewIPSetSupervisor(c, pe, ipt, ips, networks)
	if err != nil {
		t.Errorf("NewIPTables should not fail. Error received: %s", err)
		t.SkipNow()
	}
	return s.(*ipsetSupervisor)
}

func TestNewIPSetSupervisor(t *testing.T) {

	c := &collector.DefaultCollector{}
	pe := mockenforcerDefaultFQConfig(t)
	ipt := provider.NewTestIptablesProvider()
	ips := provider.NewTestIpsetProvider()
	networks := []string{"0.0.0.0/0"}

	// Test with normal parameters
	_, err := NewIPSetSupervisor(c, pe, ipt, ips, networks)
	if err != nil {
		t.Errorf("NewIPTables should not fail. Error received: %s", err)
	}
	// Test with Empty Collector
	_, err = NewIPSetSupervisor(nil, pe, ipt, ips, networks)
	if err == nil {
		t.Errorf("NewIPTables should fail because of empty Collector. No Error received.")
	}

	// Test with Empty Enforcer
	_, err = NewIPSetSupervisor(c, nil, ipt, ips, networks)
	if err == nil {
		t.Errorf("NewIPTables should fail because of empty Enforcer. No Error received.")
	}

	// Test with Empty iptables
	_, err = NewIPSetSupervisor(c, pe, nil, ips, networks)
	if err == nil {
		t.Errorf("NewIPTables should fail because of empty IPTables Provider. No Error received.")
	}

	// Test with Empty Networks
	_, err = NewIPSetSupervisor(c, pe, ipt, ips, nil)
	if err == nil {
		t.Errorf("NewIPTables should fail because of empty TriremeNetworks. No Error received.")
	}
}

func TestIPSetSupervise(t *testing.T) {
	s := doNewIPSetSupervisor(t)

	// Test empty ContainerInfo
	err := s.Supervise("123", nil)
	if err == nil {
		t.Errorf("Empty containerInfo should result in Error")
	}

	containerInfo := policy.NewPUInfo("12345")
	containerInfo.Runtime.SetIPAddresses(map[string]string{"bridge": "30.30.30.30"})
	containerInfo.Policy.PolicyIPs = []string{"30.30.30.30"}

	// Test expected parameters. Create case
	err = s.Supervise("12345", containerInfo)
	if err != nil {
		t.Errorf("Got error on create %s", err)
	}

	// Test expected parameters. Update case
	err = s.Supervise("12345", containerInfo)
	if err != nil {
		t.Errorf("Got error on Update %s", err)
	}

	containerInfo = policy.NewPUInfo("1234567")
	// Test no IP parameters. Create case
	err = s.Supervise("1234567", containerInfo)
	if err == nil {
		t.Errorf("No Error even though IP not part of Policy")
	}
}

func TestIPSetUnsupervise(t *testing.T) {
	s := doNewIPSetSupervisor(t)

	// Test Unsupervise for nonexistingContainer. Should return an error
	err := s.Unsupervise("123")
	if err == nil {
		t.Errorf("Empty containerInfo should result in Error")
	}

	containerInfo := policy.NewPUInfo("12345")
	containerInfo.Runtime.SetIPAddresses(map[string]string{"bridge": "30.30.30.30"})
	containerInfo.Policy.PolicyIPs = []string{"30.30.30.30"}

	// Test expected parameters. Create case
	err = s.Supervise("12345", containerInfo)
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

func TestIPSetStart(t *testing.T) {
	s := doNewIPSetSupervisor(t)
	err := s.Start()
	if err != nil {
		t.Errorf("Start should not return an errir: %s", err)
	}
}

func TestIPSetStop(t *testing.T) {
	s := doNewIPSetSupervisor(t)
	s.Start()
	err := s.Stop()
	if err != nil {
		t.Errorf("Stop should not return an errir: %s", err)
	}
}
