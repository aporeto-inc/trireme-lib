package supervisor

import (
	"reflect"
	"testing"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	// "github.com/aporeto-inc/trireme/policy"
	"github.com/coreos/go-iptables/iptables"
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
	networks := []string{"0.0.0.0/0"}
	s, err := NewIPTablesSupervisor(c, pe, networks)
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
	_, err := iptables.New()
	if err != nil {
		t.Logf("IPTables not present on this system, not testing")
		t.SkipNow()
	}

	doNewIPTSupervisor(t)

}

/*
func TestSupervise(t *testing.T) {
	_, err := iptables.New()
	if err != nil {
		t.Logf("IPTables not present on this system, not testing")
		t.SkipNow()
	}
	s := doNewIPTSupervisor(t)
	containerInfo := policy.NewPUInfo("12345")

	containerInfo.Runtime.SetIPAddresses(map[string]string{"bridge": "127.0.0.1"})

	err = s.Supervise("12345", containerInfo)
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
*/
