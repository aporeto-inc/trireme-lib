package trireme

import (
	"fmt"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor"

	"github.com/golang/glog"
)

// trireme contains references to all the different components involved.
type trireme struct {
	serverID   string
	cache      cache.DataStore
	supervisor supervisor.Supervisor
	enforcer   enforcer.PolicyEnforcer
	resolver   PolicyResolver
	stop       chan bool
	requests   chan *triremeRequest
}

// NewTrireme returns a reference to the trireme object based on the parameter subelements.
func NewTrireme(serverID string, resolver PolicyResolver, supervisor supervisor.Supervisor, enforcer enforcer.PolicyEnforcer) Trireme {

	trireme := &trireme{
		serverID:   serverID,
		cache:      cache.NewCache(nil),
		supervisor: supervisor,
		enforcer:   enforcer,
		resolver:   resolver,
		stop:       make(chan bool),
		requests:   make(chan *triremeRequest),
	}

	resolver.SetPolicyUpdater(trireme)

	return trireme
}

// Start starts the supervisor and the enforcer. It will also start to handling requests
// For new PU Creation and Policy Updates.
func (t *trireme) Start() error {

	if err := t.supervisor.Start(); err != nil {
		return fmt.Errorf("Error starting Controller: %s", err)
	}

	if err := t.enforcer.Start(); err != nil {
		return fmt.Errorf("Error starting enforcer: %s", err)
	}

	// Starting main trireme routine
	go t.run()

	return nil
}

// Stop stops the supervisor and enforcer. It also stops handling new request
// for PU Creation/Update and Policy Updates
func (t *trireme) Stop() error {

	// send the stop signal for the trireme worker routine.
	t.stop <- true

	if err := t.supervisor.Stop(); err != nil {
		return fmt.Errorf("Error stopping Controller: %s", err)
	}

	if err := t.enforcer.Stop(); err != nil {
		return fmt.Errorf("Error stopping enforcer: %s", err)
	}

	return nil
}

// HandleCreate implements the logic needed between all the Trireme components for
// explicitely adding a new PU.
func (t *trireme) HandleCreate(contextID string, runtimeInfo *policy.PURuntime) <-chan error {

	c := make(chan error)

	req := &triremeRequest{
		contextID:   contextID,
		reqType:     requestCreate,
		runtimeInfo: runtimeInfo,
		returnChan:  c,
	}

	t.requests <- req

	return c
}

// HandleDelete implements the logic needed between all the Trireme components for
// explicitely deleting an existing PU.
func (t *trireme) HandleDelete(contextID string) <-chan error {

	c := make(chan error)

	req := &triremeRequest{
		contextID:  contextID,
		reqType:    requestDelete,
		returnChan: c,
	}

	t.requests <- req

	return c
}

// UpdatePolicy updates a policy for an already activated PU. The PU is identified by the contextID
func (t *trireme) UpdatePolicy(contextID string, newPolicy *policy.PUPolicy) <-chan error {

	c := make(chan error)

	req := &triremeRequest{
		contextID:  contextID,
		reqType:    policyUpdate,
		policyInfo: newPolicy,
		returnChan: c,
	}

	t.requests <- req

	return c
}

// PURuntime returns the RuntimeInfo based on the contextID.
func (t *trireme) PURuntime(contextID string) (policy.RuntimeReader, error) {

	container, err := t.cache.Get(contextID)

	if err != nil {
		return nil, err
	}

	return container.(*policy.PURuntime), nil
}

// addTransmitterLabel adds the TransmitterLabel as a fixed label in the policy.
func addTransmitterLabel(contextID string, containerInfo *policy.PUInfo) {
	containerInfo.Policy.PolicyTags[enforcer.TransmitterLabel] = contextID
}

func (t *trireme) doHandleCreate(contextID string, runtimeInfo *policy.PURuntime) error {

	// Cache all the container runtime information
	if err := t.cache.AddOrUpdate(contextID, runtimeInfo); err != nil {
		return err
	}

	policyInfo, err := t.resolver.ResolvePolicy(contextID, runtimeInfo)
	if err != nil {
		glog.V(2).Infoln("Policy Error for this context: %s . Container killed. %s", contextID, err)
		return fmt.Errorf("Policy Error for this context: %s . Container killed. %s", contextID, err)
	}

	if policyInfo == nil {
		glog.V(2).Infoln("Nil policy returned for context: %s . Container killed.", contextID)
		return fmt.Errorf("Nil policy returned for context: %s. Container killed.", contextID)
	}

	containerInfo := policy.PUInfoFromPolicyAndRuntime(contextID, policyInfo, runtimeInfo)

	addTransmitterLabel(contextID, containerInfo)

	err = t.supervisor.Supervise(contextID, containerInfo)
	if err != nil {
		t.resolver.HandleDeletePU(contextID)
		return fmt.Errorf("Not able to setup supervisor: %s", err)
	}

	err = t.enforcer.Enforce(contextID, containerInfo)
	if err != nil {
		t.resolver.HandleDeletePU(contextID)
		t.supervisor.Unsupervise(contextID)
		return fmt.Errorf("Not able to setup enforcer: %s", err)
	}
	glog.V(2).Infoln("Finished PUHandleCreate: %s .", contextID)
	return nil
}

func (t *trireme) doHandleDelete(contextID string) error {
	_, err := t.PURuntime(contextID)
	if err != nil {
		return fmt.Errorf("Error getting Runtime out of cache for ContextID %s : %s", contextID, err)
	}

	errR := t.resolver.HandleDeletePU(contextID)
	errS := t.supervisor.Unsupervise(contextID)
	errE := t.enforcer.Unenforce(contextID)
	t.cache.Remove(contextID)
	if errR != nil || errS != nil || errE != nil {
		return fmt.Errorf("Delete Error for contextID %s. resolver %s, supervisor %s, enforcer %s", contextID, errR, errS, errE)
	}
	glog.V(5).Infof("Finished HandleDelete. %s", contextID)
	return nil
}

func (t *trireme) doUpdatePolicy(contextID string, newPolicy *policy.PUPolicy) error {
	runtimeInfo, err := t.PURuntime(contextID)
	if err != nil {
		return fmt.Errorf("Policy Update failed because couldn't find runtime for contextID %s", contextID)
	}
	containerInfo := policy.PUInfoFromPolicyAndRuntime(contextID, newPolicy, runtimeInfo.(*policy.PURuntime))

	addTransmitterLabel(contextID, containerInfo)

	err = t.supervisor.Supervise(contextID, containerInfo)
	if err != nil {
		return fmt.Errorf("Policy Update failed for Supervisor %s", err)
	}

	err = t.enforcer.Enforce(contextID, containerInfo)
	if err != nil {
		t.supervisor.Unsupervise(contextID)
		return fmt.Errorf("Policy Update failed for Enforcer %s", err)
	}
	glog.V(5).Infof("Finished UpdatePolicy. %s", contextID)
	return nil
}

func (t *trireme) handleRequest(request *triremeRequest) error {
	switch request.reqType {
	case requestCreate:
		return t.doHandleCreate(request.contextID, request.runtimeInfo)
	case requestDelete:
		return t.doHandleDelete(request.contextID)
	case policyUpdate:
		return t.doUpdatePolicy(request.contextID, request.policyInfo)
	default:
		return fmt.Errorf("trireme Request format not recognized: %d", request.reqType)
	}
}

func (t *trireme) run() {
	for {
		select {
		case <-t.stop:
			glog.V(2).Infof("Stopping trireme worker.")
			return
		case req := <-t.requests:
			glog.V(5).Infof("Handling trireme Request Type %d ", req.reqType)
			req.returnChan <- t.handleRequest(req)
		}
	}
}
