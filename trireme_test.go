package trireme

import (
	"reflect"
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

func doTestCreate(t *testing.T, trireme Trireme, tresolver TestPolicyResolver, tsupervisor supervisor.TestSupervisor, tenforcer enforcer.TestPolicyEnforcer, tmonitor monitor.TestMonitor, id string, runtime *policy.PURuntime) {

	resolverCount := 0
	supervisorCount := 0
	enforcerCount := 0

	tresolver.MockResolvePolicy(t, func(contextID string, RuntimeReader policy.RuntimeReader) (*policy.PUPolicy, error) {
		t.Logf("Into ResolvePolicy")
		if contextID != id {
			t.Errorf("Id in Resolve was expected to be %s, but is %s", id, contextID)
		}

		if !reflect.DeepEqual(runtime, RuntimeReader) {
			t.Errorf("Runtime given to Resolver is not the same. Received %v, expected %v", RuntimeReader, runtime)
		}

		tpolicy := policy.NewPUPolicy()
		resolverCount++
		return tpolicy, nil
	})

	tsupervisor.MockSupervise(t, func(contextID string, puInfo *policy.PUInfo) error {
		if contextID != id {
			t.Errorf("Id in Supervisor was expected to be %s, but is %s", id, contextID)
		}

		if !reflect.DeepEqual(runtime, puInfo.Runtime) {
			t.Errorf("Runtime given to Supervisor is not the same. Received %v, expected %v", puInfo.Runtime, runtime)
		}

		t.Logf("Into Supervise")
		supervisorCount++
		return nil
	})

	tenforcer.MockEnforce(t, func(contextID string, puInfo *policy.PUInfo) error {
		if contextID != id {
			t.Errorf("Id in Enforcer was expected to be %s, but is %s", id, contextID)
		}

		if !reflect.DeepEqual(runtime, puInfo.Runtime) {
			t.Errorf("Runtime given to Enforcer is not the same. Received %v, expected %v", puInfo.Runtime, runtime)
		}

		t.Logf("Into Enforce")
		enforcerCount++
		return nil
	})

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

func doTestDelete(t *testing.T, trireme Trireme, tresolver TestPolicyResolver, tsupervisor supervisor.TestSupervisor, tenforcer enforcer.TestPolicyEnforcer, tmonitor monitor.TestMonitor, id string, runtime *policy.PURuntime) {

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

	err := trireme.HandleDelete(id)
	if e := <-err; e != nil {
		t.Errorf("Delete was supposed to be nil, was %s", e)
	}
	if resolverCount != 1 {
		t.Errorf("Delete didn't go to Resolver")
	}
	if supervisorCount != 1 {
		t.Errorf("Delete didn't go to Supervisor")
	}
	if enforcerCount != 1 {
		t.Errorf("Delete didn't go to Enforcer")
	}
}

func doTestDeleteNotExist(t *testing.T, trireme Trireme, tresolver TestPolicyResolver, tsupervisor supervisor.TestSupervisor, tenforcer enforcer.TestPolicyEnforcer, tmonitor monitor.TestMonitor, id string, runtime *policy.PURuntime) {

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

	err := trireme.HandleDelete(id)
	if e := <-err; e == nil {
		t.Errorf("Delete was not supposed to be nil, was nil")
	}
}

func doTestUpdate(t *testing.T, trireme Trireme, tresolver TestPolicyResolver, tsupervisor supervisor.TestSupervisor, tenforcer enforcer.TestPolicyEnforcer, tmonitor monitor.TestMonitor, id string, initialRuntime *policy.PURuntime, updatedPolicy *policy.PUPolicy) {
	supervisorCount := 0
	enforcerCount := 0

	tsupervisor.MockSupervise(t, func(contextID string, puInfo *policy.PUInfo) error {

		if contextID != id {
			t.Errorf("Id in Supervisor was expected to be %s, but is %s", id, contextID)
		}

		if !reflect.DeepEqual(puInfo.Runtime, initialRuntime) {
			t.Errorf("Runtime given to Supervisor is not the same. Received %v, expected %v", puInfo.Runtime, initialRuntime)
		}

		if !reflect.DeepEqual(puInfo.Policy, updatedPolicy) {
			t.Errorf("Policy given to Supervisor is not the same. Received %v, expected %v", puInfo.Policy, updatedPolicy)
		}

		t.Logf("Into Supervise Update")
		supervisorCount++
		return nil
	})

	tenforcer.MockEnforce(t, func(contextID string, puInfo *policy.PUInfo) error {
		//		if contextID != id {
		//			t.Errorf("Id in Enforcer was expected to be %s, but is %s", id, contextID)
		//		}

		if !reflect.DeepEqual(puInfo.Runtime, initialRuntime) {
			t.Errorf("Runtime given to Supervisor is not the same. Received %v, expected %v", puInfo.Runtime, initialRuntime)
		}

		if !reflect.DeepEqual(puInfo.Policy, updatedPolicy) {
			t.Errorf("Policy given to Supervisor is not the same. Received %v, expected %v", puInfo.Policy, updatedPolicy)
		}

		t.Logf("Into Enforce Update")
		enforcerCount++
		return nil
	})

	err := trireme.UpdatePolicy(id, updatedPolicy)
	if e := <-err; e != nil {
		t.Errorf("Update was supposed to be nil, was %s", e)
	}

	if supervisorCount != 1 {
		t.Errorf("Update didn't go to Supervisor")
	}
	if enforcerCount != 1 {
		t.Errorf("Update didn't go to Enforcer")
	}

}

func TestSimpleCreate(t *testing.T) {
	tresolver, tsupervisor, tenforcer, tmonitor := createMocks()
	trireme := NewTrireme("serverID", tresolver, tsupervisor, tenforcer)
	trireme.Start()
	contextID := "123123"
	runtime := policy.NewPURuntime()

	doTestCreate(t, trireme, tresolver, tsupervisor, tenforcer, tmonitor, contextID, runtime)
}

func TestSimpleDelete(t *testing.T) {
	tresolver, tsupervisor, tenforcer, tmonitor := createMocks()
	trireme := NewTrireme("serverID", tresolver, tsupervisor, tenforcer)
	trireme.Start()
	contextID := "123123"
	runtime := policy.NewPURuntime()

	doTestDeleteNotExist(t, trireme, tresolver, tsupervisor, tenforcer, tmonitor, contextID, runtime)
}

func TestCreateDelete(t *testing.T) {
	tresolver, tsupervisor, tenforcer, tmonitor := createMocks()
	trireme := NewTrireme("serverID", tresolver, tsupervisor, tenforcer)
	trireme.Start()
	contextID := "123123"
	runtime := policy.NewPURuntime()

	doTestCreate(t, trireme, tresolver, tsupervisor, tenforcer, tmonitor, contextID, runtime)
	doTestDelete(t, trireme, tresolver, tsupervisor, tenforcer, tmonitor, contextID, runtime)
}

func TestSimpleUpdate(t *testing.T) {
	tresolver, tsupervisor, tenforcer, tmonitor := createMocks()
	trireme := NewTrireme("serverID", tresolver, tsupervisor, tenforcer)
	trireme.Start()
	contextID := "123123"
	runtime := policy.NewPURuntime()
	ipa := map[string]string{"bridge": "10.10.10.10"}
	runtime.SetIPAddresses(ipa)

	doTestCreate(t, trireme, tresolver, tsupervisor, tenforcer, tmonitor, contextID, runtime)

	// Generate a new Policy ...

	newPolicy := policy.NewPUPolicy()
	doTestUpdate(t, trireme, tresolver, tsupervisor, tenforcer, tmonitor, contextID, runtime, newPolicy)
}

func TestCache(t *testing.T) {
	tresolver, tsupervisor, tenforcer, tmonitor := createMocks()
	trireme := NewTrireme("serverID", tresolver, tsupervisor, tenforcer)
	trireme.Start()
	contextID := "123123"
	runtime := policy.NewPURuntime()

	for i := 0; i < 5; i++ {
		doTestCreate(t, trireme, tresolver, tsupervisor, tenforcer, tmonitor, contextID, runtime)

		// Expecting cache to find it
		cacheRuntime, err := trireme.PURuntime(contextID)
		if err != nil {
			t.Errorf("Cache failed. No Error expected, but error returned %v", err)
		}

		if !reflect.DeepEqual(runtime, cacheRuntime) {
			t.Errorf("Cache failed. Expected %v, got %v", runtime, cacheRuntime)
		}

		doTestDelete(t, trireme, tresolver, tsupervisor, tenforcer, tmonitor, contextID, runtime)

		// Expecting cache to not find it
		_, err = trireme.PURuntime(contextID)
		if err == nil {
			t.Errorf("Cache succeeded. Error expected, but No error returned ")
		}
	}
}

func TestStop(t *testing.T) {
	tresolver, tsupervisor, tenforcer, tmonitor := createMocks()
	trireme := NewTrireme("serverID", tresolver, tsupervisor, tenforcer)
	trireme.Start()
	contextID := "123123"
	runtime := policy.NewPURuntime()

	doTestCreate(t, trireme, tresolver, tsupervisor, tenforcer, tmonitor, contextID, runtime)

	trireme.Stop()
	trireme.Start()
	doTestCreate(t, trireme, tresolver, tsupervisor, tenforcer, tmonitor, contextID, runtime)
}
