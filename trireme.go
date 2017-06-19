package trireme

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/proxy"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor"
)

// trireme contains references to all the different components involved.
type trireme struct {
	serverID    string
	cache       cache.DataStore
	supervisors map[constants.PUType]supervisor.Supervisor
	enforcers   map[constants.PUType]enforcer.PolicyEnforcer
	resolver    PolicyResolver
	collector   collector.EventCollector
	stop        chan bool
	requests    chan *triremeRequest
}

// NewTrireme returns a reference to the trireme object based on the parameter subelements.
func NewTrireme(serverID string, resolver PolicyResolver, supervisors map[constants.PUType]supervisor.Supervisor, enforcers map[constants.PUType]enforcer.PolicyEnforcer, eventCollector collector.EventCollector) Trireme {

	trireme := &trireme{
		serverID:    serverID,
		cache:       cache.NewCache(),
		supervisors: supervisors,
		enforcers:   enforcers,
		resolver:    resolver,
		collector:   eventCollector,
		stop:        make(chan bool),
		requests:    make(chan *triremeRequest),
	}

	return trireme
}

// Start starts the supervisor and the enforcer. It will also start to handling requests
// For new PU Creation and Policy Updates.
func (t *trireme) Start() error {

	// Start all the supervisors
	for _, s := range t.supervisors {
		if err := s.Start(); err != nil {
			zap.L().Error("Error when starting the supervisor", zap.Error(err)) // really? just a warn?
		}
	}

	// Start all the enforcers
	for _, e := range t.enforcers {
		if err := e.Start(); err != nil {
			return fmt.Errorf("Error while starting the enforcer: %s", err)
		}
	}

	// Starting main trireme routine
	go t.run()

	return nil
}

// Stop stops the supervisor and enforcer. It also stops handling new request
// for PU Creation/Update and Policy Updates
func (t *trireme) Stop() error {

	for _, s := range t.supervisors {
		if err := s.Stop(); err != nil {
			zap.L().Error("Error when stopping the supervisor", zap.Error(err))
		}
	}

	for _, e := range t.enforcers {
		if err := e.Stop(); err != nil {
			zap.L().Error("Error when stopping the enforcer", zap.Error(err))
		}
	}

	// send the stop signal for the trireme worker routine.
	t.stop <- true

	return nil
}

// HandlePUEvent implements the logic needed between all the Trireme components for
// explicitly adding a new PU.
func (t *trireme) HandlePUEvent(contextID string, event monitor.Event) <-chan error {

	c := make(chan error, 1)

	req := &triremeRequest{
		contextID:  contextID,
		reqType:    handleEvent,
		eventType:  event,
		returnChan: c,
	}

	t.requests <- req

	return c
}

// UpdatePolicy updates a policy for an already activated PU. The PU is identified by the contextID
func (t *trireme) UpdatePolicy(contextID string, newPolicy *policy.PUPolicy) <-chan error {

	c := make(chan error, 1)

	req := &triremeRequest{
		contextID:  contextID,
		reqType:    policyUpdate,
		policyInfo: newPolicy.Clone(),
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

// SetPURuntime returns the RuntimeInfo based on the contextID.
func (t *trireme) SetPURuntime(contextID string, runtimeInfo *policy.PURuntime) error {

	t.cache.AddOrUpdate(contextID, runtimeInfo)

	return nil

}

// addTransmitterLabel adds the TransmitterLabel as a fixed label in the policy.
// The ManagementID part of the policy is used as the TransmitterLabel.
// If the Policy didn't set the ManagementID, we use the Local contextID as the
// default TransmitterLabel.
func addTransmitterLabel(contextID string, containerInfo *policy.PUInfo) {

	if containerInfo.Policy.ManagementID == "" {
		containerInfo.Policy.AddIdentityTag(enforcer.TransmitterLabel, contextID)
	} else {
		containerInfo.Policy.AddIdentityTag(enforcer.TransmitterLabel, containerInfo.Policy.ManagementID)
	}
}

// MustEnforce returns true if the Policy should go Through the Enforcer/Supervisor.
// Return false if:
//   - PU is in host namespace.
//   - Policy got the AllowAll tag.
func mustEnforce(contextID string, containerInfo *policy.PUInfo) bool {

	if containerInfo.Policy.TriremeAction == policy.AllowAll {
		zap.L().Debug("PUPolicy with AllowAll Action. Not policing", zap.String("contextID", contextID))
		return false
	}

	return true
}

func (t *trireme) doHandleCreate(contextID string) error {

	// Retrieve the container runtime information from the cache
	cachedElement, err := t.cache.Get(contextID)
	if err != nil {
		t.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: "N/A",
			Tags:      nil,
			Event:     collector.ContainerFailed,
		})

		return fmt.Errorf("Couldn't get the runtimeInfo from the cache %s", err)
	}

	runtimeInfo := cachedElement.(*policy.PURuntime)

	policyInfo, err := t.resolver.ResolvePolicy(contextID, runtimeInfo)

	if err != nil {
		t.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: "N/A",
			Tags:      nil,
			Event:     collector.ContainerFailed,
		})

		return fmt.Errorf("Policy Error for this context: %s. Container killed. %s", contextID, err)
	}

	if policyInfo == nil {
		t.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: "N/A",
			Tags:      nil,
			Event:     collector.ContainerFailed,
		})

		return fmt.Errorf("Nil policy returned for context: %s. Container killed", contextID)
	}

	ip, _ := policyInfo.DefaultIPAddress()

	// Create a copy as we are going to modify it locally
	policyInfo = policyInfo.Clone()

	containerInfo := policy.PUInfoFromPolicyAndRuntime(contextID, policyInfo, runtimeInfo)

	addTransmitterLabel(contextID, containerInfo)

	if !mustEnforce(contextID, containerInfo) {
		t.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: ip,
			Tags:      policyInfo.Annotations(),
			Event:     collector.ContainerIgnored,
		})
		return nil
	}

	if err := t.enforcers[containerInfo.Runtime.PUType()].Enforce(contextID, containerInfo); err != nil {
		t.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: ip,
			Tags:      policyInfo.Annotations(),
			Event:     collector.ContainerFailed,
		})
		return fmt.Errorf("Not able to setup enforcer: %s", err)
	}

	if err := t.supervisors[containerInfo.Runtime.PUType()].Supervise(contextID, containerInfo); err != nil {
		if werr := t.enforcers[containerInfo.Runtime.PUType()].Unenforce(contextID); werr != nil {
			zap.L().Warn("Failed to clean up state after failures",
				zap.String("contextID", contextID),
				zap.Error(werr),
			)
		}

		t.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: ip,
			Tags:      policyInfo.Annotations(),
			Event:     collector.ContainerFailed,
		})

		return fmt.Errorf("Not able to setup supervisor: %s", err)
	}

	t.collector.CollectContainerEvent(&collector.ContainerRecord{
		ContextID: contextID,
		IPAddress: ip,
		Tags:      containerInfo.Policy.Annotations(),
		Event:     collector.ContainerStart,
	})

	return nil
}

func (t *trireme) doHandleDelete(contextID string) error {

	runtime, err := t.PURuntime(contextID)

	if err != nil {
		t.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: "N/A",
			Tags:      nil,
			Event:     collector.UnknownContainerDelete,
		})

		return fmt.Errorf("Error getting Runtime out of cache for ContextID %s: %s", contextID, err)
	}

	ip, _ := runtime.DefaultIPAddress()

	errS := t.supervisors[runtime.PUType()].Unsupervise(contextID)
	errE := t.enforcers[runtime.PUType()].Unenforce(contextID)

	if err := t.cache.Remove(contextID); err != nil {
		zap.L().Warn("Failed to remove context from cache during cleanup. Entry doesn't exist",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	if errS != nil || errE != nil {
		t.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: ip,
			Tags:      nil,
			Event:     collector.ContainerDelete,
		})

		return fmt.Errorf("Delete Error for contextID %s. supervisor %s, enforcer %s", contextID, errS, errE)
	}

	t.collector.CollectContainerEvent(&collector.ContainerRecord{
		ContextID: contextID,
		IPAddress: ip,
		Tags:      nil,
		Event:     collector.ContainerDelete,
	})

	return nil
}

func (t *trireme) doHandleEvent(contextID string, event monitor.Event) error {
	// Notify The PolicyResolver that an event occurred:
	t.resolver.HandlePUEvent(contextID, event)

	switch event {
	case monitor.EventStart:
		return t.doHandleCreate(contextID)
	case monitor.EventStop:
		return t.doHandleDelete(contextID)
	default:
		return nil
	}
}

func (t *trireme) doUpdatePolicy(contextID string, newPolicy *policy.PUPolicy) error {

	runtimeInfo, err := t.PURuntime(contextID)

	if err != nil {
		return fmt.Errorf("Policy Update failed because couldn't find runtime for contextID %s", contextID)
	}

	containerInfo := policy.PUInfoFromPolicyAndRuntime(contextID, newPolicy, runtimeInfo.(*policy.PURuntime))

	addTransmitterLabel(contextID, containerInfo)

	if !mustEnforce(contextID, containerInfo) {
		return nil
	}

	if err = t.enforcers[containerInfo.Runtime.PUType()].Enforce(contextID, containerInfo); err != nil {
		if err != nil {
			//We lost communication with the remote and killed it lets restart it here by feeding a create event in the request channel
			zap.L().Debug("We lost communication with enforcer lets restart")

			if containerInfo.Runtime.PUType() == constants.ContainerPU {
				//The unsupervise and unenforce functions just make changes to the proxy structures
				//and do not depend on the remote instance running and can be called here
				switch t.enforcers[containerInfo.Runtime.PUType()].(type) {
				case *enforcerproxy.ProxyInfo:
					t.enforcers[containerInfo.Runtime.PUType()].Unenforce(contextID)
					t.supervisors[containerInfo.Runtime.PUType()].Unsupervise(contextID)
					t.doHandleCreate(contextID)
				default:
					//do nothing

				}

			}
		}
		return fmt.Errorf("Enforcer failed to update PU policy: context=%s error=%s", contextID, err)
	}

	if err = t.supervisors[containerInfo.Runtime.PUType()].Supervise(contextID, containerInfo); err != nil {
		if werr := t.enforcers[containerInfo.Runtime.PUType()].Unenforce(contextID); werr != nil {
			zap.L().Warn("Failed to clean up after enforcerments failures",
				zap.String("contextID", contextID),
				zap.Error(werr),
			)
		}
		return fmt.Errorf("Supervisor failed to update PU policy: context=%s error=%s", contextID, err)
	}

	ip, _ := newPolicy.DefaultIPAddress()
	t.collector.CollectContainerEvent(&collector.ContainerRecord{
		ContextID: contextID,
		IPAddress: ip,
		Tags:      containerInfo.Runtime.Tags(),
		Event:     collector.ContainerUpdate,
	})

	return nil
}

func (t *trireme) handleRequest(request *triremeRequest) error {
	switch request.reqType {
	case handleEvent:
		return t.doHandleEvent(request.contextID, request.eventType)
	case policyUpdate:
		return t.doUpdatePolicy(request.contextID, request.policyInfo)
	default:
		return fmt.Errorf("Trireme Request format not recognized: %d", request.reqType)
	}
}

// Supervisor returns the Trireme supervisor for the given PU Type
func (t *trireme) Supervisor(kind constants.PUType) supervisor.Supervisor {

	if s, ok := t.supervisors[kind]; ok {
		return s
	}

	return nil
}

// run is the main function for running Trireme
func (t *trireme) run() {
	for {
		select {
		case req := <-t.requests:
			zap.L().Debug("Handling Trireme Request",
				zap.Int("type", req.reqType),
				zap.String("contextID", req.contextID),
			)
			req.returnChan <- t.handleRequest(req)
		case <-t.stop:
			zap.L().Debug("Stopping trireme worker.")
			return
		}
	}
}
