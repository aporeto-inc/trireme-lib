package trireme

import (
	"reflect"
	"testing"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor"
)

func createMocks() (TestPolicyResolver, map[constants.PUType]supervisor.Supervisor, map[constants.PUType]enforcer.PolicyEnforcer, monitor.TestMonitor, collector.EventCollector) {
	tresolver := NewTestPolicyResolver()
	s := supervisor.NewTestSupervisor()
	tsupervisor := map[constants.PUType]supervisor.Supervisor{constants.ContainerPU: s}

	tenforcer := map[constants.PUType]enforcer.PolicyEnforcer{constants.ContainerPU: enforcer.NewTestPolicyEnforcer()}
	tmonitor := monitor.NewTestMonitor()
	tcollector := &collector.DefaultCollector{}
	return tresolver, tsupervisor, tenforcer, tmonitor, tcollector
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

		ipaddrs := policy.NewIPMap(map[string]string{policy.DefaultNamespace: "127.0.0.1"})
		tpolicy := policy.NewPUPolicy("SomeId", policy.Police, nil, nil, nil, nil, nil, nil, ipaddrs, []string{"172.17.0.0/24"}, []string{}, nil)
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

	e := trireme.SetPURuntime(id, runtime)
	if e != nil {
		t.Errorf("Error while setting the Runtime in Trireme,  %s", e)
	}
	err := trireme.HandlePUEvent(id, monitor.EventStart)
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

	tresolver.MockHandlePUEvent(t, func(contextID string, eventType monitor.Event) {
		t.Logf("Into HandleDeletePU")
		if eventType == monitor.EventStop {
			resolverCount++
		}
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

	err := trireme.HandlePUEvent(id, monitor.EventStop)
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

	tresolver.MockHandlePUEvent(t, func(contextID string, eventType monitor.Event) {
		t.Logf("Into HandleDeletePU")
		resolverCount++
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

	err := trireme.HandlePUEvent(id, monitor.EventStop)
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
	tresolver, tsupervisor, tenforcer, tmonitor, tcollector := createMocks()
	trireme := NewTrireme("serverID", tresolver, tsupervisor, tenforcer, tcollector)
	if err := trireme.Start(); err != nil {
		t.Errorf("Failed to start trireme")
	}
	contextID := "123123"
	runtime := policy.NewPURuntimeWithDefaults()

	doTestCreate(t, trireme, tresolver, tsupervisor[constants.ContainerPU].(supervisor.TestSupervisor), tenforcer[constants.ContainerPU].(enforcer.TestPolicyEnforcer), tmonitor, contextID, runtime)
}

func TestSimpleDelete(t *testing.T) {
	tresolver, tsupervisor, tenforcer, tmonitor, tcollector := createMocks()
	trireme := NewTrireme("serverID", tresolver, tsupervisor, tenforcer, tcollector)
	if err := trireme.Start(); err != nil {
		t.Errorf("Failed to start trireme")
	}
	contextID := "123123"
	runtime := policy.NewPURuntimeWithDefaults()

	doTestDeleteNotExist(t, trireme, tresolver, tsupervisor[constants.ContainerPU].(supervisor.TestSupervisor), tenforcer[constants.ContainerPU].(enforcer.TestPolicyEnforcer), tmonitor, contextID, runtime)
}

func TestCreateDelete(t *testing.T) {
	tresolver, tsupervisor, tenforcer, tmonitor, tcollector := createMocks()
	trireme := NewTrireme("serverID", tresolver, tsupervisor, tenforcer, tcollector)
	if err := trireme.Start(); err != nil {
		t.Errorf("Failed to start trireme")
	}
	contextID := "123123"
	runtime := policy.NewPURuntimeWithDefaults()

	doTestCreate(t, trireme, tresolver, tsupervisor[constants.ContainerPU].(supervisor.TestSupervisor), tenforcer[constants.ContainerPU].(enforcer.TestPolicyEnforcer), tmonitor, contextID, runtime)
	doTestDelete(t, trireme, tresolver, tsupervisor[constants.ContainerPU].(supervisor.TestSupervisor), tenforcer[constants.ContainerPU].(enforcer.TestPolicyEnforcer), tmonitor, contextID, runtime)
}

func TestSimpleUpdate(t *testing.T) {
	tresolver, tsupervisor, tenforcer, tmonitor, tcollector := createMocks()
	trireme := NewTrireme("serverID", tresolver, tsupervisor, tenforcer, tcollector)
	if err := trireme.Start(); err != nil {
		t.Errorf("Failed to start trireme")
	}
	contextID := "123123"
	runtime := policy.NewPURuntimeWithDefaults()
	ipa := policy.NewIPMap(map[string]string{
		"bridge": "10.10.10.10",
	})
	runtime.SetIPAddresses(ipa)

	doTestCreate(t, trireme, tresolver, tsupervisor[constants.ContainerPU].(supervisor.TestSupervisor), tenforcer[constants.ContainerPU].(enforcer.TestPolicyEnforcer), tmonitor, contextID, runtime)

	// Generate a new Policy ...
	ipl := policy.NewIPMap(map[string]string{policy.DefaultNamespace: "127.0.0.1"})
	tagsMap := policy.NewTagsMap(map[string]string{enforcer.TransmitterLabel: contextID})
	newPolicy := policy.NewPUPolicy("", policy.Police, nil, nil, nil, nil, tagsMap, nil, ipl, []string{"172.17.0.0/24"}, []string{}, nil)
	doTestUpdate(t, trireme, tresolver, tsupervisor[constants.ContainerPU].(supervisor.TestSupervisor), tenforcer[constants.ContainerPU].(enforcer.TestPolicyEnforcer), tmonitor, contextID, runtime, newPolicy)
}

func TestCache(t *testing.T) {
	tresolver, tsupervisor, tenforcer, tmonitor, tcollector := createMocks()
	trireme := NewTrireme("serverID", tresolver, tsupervisor, tenforcer, tcollector)
	if err := trireme.Start(); err != nil {
		t.Errorf("Failed to start trireme")
	}
	contextID := "123123"
	runtime := policy.NewPURuntimeWithDefaults()

	for i := 0; i < 5; i++ {
		doTestCreate(t, trireme, tresolver, tsupervisor[constants.ContainerPU].(supervisor.TestSupervisor), tenforcer[constants.ContainerPU].(enforcer.TestPolicyEnforcer), tmonitor, contextID, runtime)

		// Expecting cache to find it
		cacheRuntime, err := trireme.PURuntime(contextID)
		if err != nil {
			t.Errorf("Cache failed. No Error expected, but error returned %v", err)
		}

		if !reflect.DeepEqual(runtime, cacheRuntime) {
			t.Errorf("Cache failed. Expected %v, got %v", runtime, cacheRuntime)
		}

		doTestDelete(t, trireme, tresolver, tsupervisor[constants.ContainerPU].(supervisor.TestSupervisor), tenforcer[constants.ContainerPU].(enforcer.TestPolicyEnforcer), tmonitor, contextID, runtime)

		// Expecting cache to not find it
		_, err = trireme.PURuntime(contextID)
		if err == nil {
			t.Errorf("Cache succeeded. Error expected, but No error returned ")
		}
	}
}

func TestStop(t *testing.T) {
	tresolver, tsupervisor, tenforcer, tmonitor, tcollector := createMocks()
	trireme := NewTrireme("serverID", tresolver, tsupervisor, tenforcer, tcollector)
	if err := trireme.Start(); err != nil {
		t.Errorf("Failed to start trireme")
	}
	contextID := "123123"
	runtime := policy.NewPURuntimeWithDefaults()

	doTestCreate(t, trireme, tresolver, tsupervisor[constants.ContainerPU].(supervisor.TestSupervisor), tenforcer[constants.ContainerPU].(enforcer.TestPolicyEnforcer), tmonitor, contextID, runtime)

	if err := trireme.Stop(); err != nil {
		t.Errorf("Failed to stop trireme ")
	}

	if err := trireme.Start(); err != nil {
		t.Errorf("Failed to start trireme")
	}
	doTestCreate(t, trireme, tresolver, tsupervisor[constants.ContainerPU].(supervisor.TestSupervisor), tenforcer[constants.ContainerPU].(enforcer.TestPolicyEnforcer), tmonitor, contextID, runtime)
}

func TestTransmitterLabel(t *testing.T) {

	// If management ID is set, use it as the TransmitterLabel

	mgmtID := "mgmt"
	contextID := "Context"
	containerInfo := policy.NewPUInfo(contextID, constants.ContainerPU)
	containerInfo.Policy.ManagementID = mgmtID
	addTransmitterLabel(contextID, containerInfo)
	label, ok := containerInfo.Policy.Identity().Get(enforcer.TransmitterLabel)
	if !ok {
		t.Errorf("Expecting Transmitter label to be set but it is missing")
	}
	if label != mgmtID {
		t.Errorf("Expecting Transmitter label to be set to MgmtID: %s , but was set to: %s", mgmtID, label)
	}

	// If management ID is not set, use contextID as the TransmitterLabel

	contextID = "Context"
	containerInfo = policy.NewPUInfo(contextID, constants.ContainerPU)
	addTransmitterLabel(contextID, containerInfo)
	label, ok = containerInfo.Policy.Identity().Get(enforcer.TransmitterLabel)
	if !ok {
		t.Errorf("Expecting Transmitter label to be set but it is missing")
	}
	if label != contextID {
		t.Errorf("Expecting Transmitter label to be set to ContextID: %s , but was set to: %s", contextID, label)
	}

}
