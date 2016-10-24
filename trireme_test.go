package trireme

import (
	"testing"

	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor"
)

func createMocks() (TestPolicyResolver, supervisor.TestSupervisor, enforcer.TestPolicyEnforcer, monitor.TestMonitor) {
	tresolver := NewTestPolicyResolver()
	tsupervisor := supervisor.NewTestSupervisor()
	tenforcer := enforcer.NewTestPolicyEnforcer()
	tmonitor := monitor.NewTestMonitor()
	return tresolver, tsupervisor, tenforcer, tmonitor
}

func TestCreate(t *testing.T) {
	tresolver, tsupervisor, tenforcer, _ := createMocks()
	trireme := NewTrireme("serverID", tresolver, tsupervisor, tenforcer)
	trireme.Start()

	id := "123123"

	resolverCount := 0
	supervisorCount := 0
	enforcerCount := 0

	tresolver.MockResolvePolicy(t, func(contextID string, RuntimeReader policy.RuntimeReader) (*policy.PUPolicy, error) {
		t.Logf("Into ResolvePolicy")
		if contextID != id {
			t.Errorf("Id in Resolve was expected to be %s, but is %s", id, contextID)
		}
		tpolicy := policy.NewPUPolicy()
		resolverCount++
		return tpolicy, nil
	})

	tsupervisor.MockSupervise(t, func(contextID string, puInfo *policy.PUInfo) error {
		if contextID != id {
			t.Errorf("Id in Resolve was expected to be %s, but is %s", id, contextID)
		}
		t.Logf("Into Supervise")
		supervisorCount++
		return nil
	})

	tenforcer.MockEnforce(t, func(contextID string, puInfo *policy.PUInfo) error {
		if contextID != id {
			t.Errorf("Id in Resolve was expected to be %s, but is %s", id, contextID)
		}
		t.Logf("Into Enforce")
		enforcerCount++
		return nil
	})

	runtime := policy.NewPURuntime()

	err := trireme.HandleCreate(id, runtime)
	if e := <-err; e != nil {
		t.Errorf("Create was supposed to be nil, was %s", e)
	}

	if resolverCount != 1 {
		t.Errorf("Create didn't go to Resolver")
	}
	if supervisorCount != 1 {
		t.Errorf("Create didn't go to Supervisor")
	}
	if enforcerCount != 1 {
		t.Errorf("Create didn't go to Enforcer")
	}

}

func TestDeleteNotpreviouslyActivatedPU(t *testing.T) {
	tresolver, tsupervisor, tenforcer, _ := createMocks()
	trireme := NewTrireme("serverID", tresolver, tsupervisor, tenforcer)
	trireme.Start()

	resolverCount := 0
	supervisorCount := 0
	enforcerCount := 0

	tresolver.MockHandleDeletePU(t, func(contextID string) error {
		t.Logf("Into HandleDeletePU")
		resolverCount++
		return nil
	})

	tsupervisor.MockUnsupervise(t, func(contextID string) error {
		t.Logf("Into Unsupervise")
		supervisorCount++
		return nil
	})

	tenforcer.MockUnenforce(t, func(ip string) error {
		t.Logf("Into Unenforce")
		enforcerCount++
		return nil
	})

	err := trireme.HandleDelete("12345")
	if e := <-err; e == nil {
		t.Errorf("Delete was not supposed to be nil, was %s", e)
	}
}
