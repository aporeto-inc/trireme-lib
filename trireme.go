package trireme

import (
	"fmt"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor"

	log "github.com/Sirupsen/logrus"
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
			log.WithFields(log.Fields{
				"package": "trireme",
				"error":   err.Error(),
			}).Debug("Error when starting the supervisor")
		}
	}

	// Start all the enforcers
	for _, e := range t.enforcers {
		if err := e.Start(); err != nil {
			log.WithFields(log.Fields{
				"package": "trireme",
				"error":   err.Error(),
			}).Debug("Error when starting the enforcer")
			return fmt.Errorf("Error starting enforcer: %s", err)
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
			log.WithFields(log.Fields{
				"package": "trireme",
				"error":   err.Error(),
			}).Debug("Error when stopping the controller")
		}
	}

	for _, e := range t.enforcers {
		if err := e.Stop(); err != nil {
			log.WithFields(log.Fields{
				"package": "trireme",
				"error":   err.Error(),
			}).Debug("Error when stopping the enforcer")
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

	return t.cache.AddOrUpdate(contextID, runtimeInfo)

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
		log.WithFields(log.Fields{
			"package":   "trireme",
			"contextID": contextID,
		}).Debug("PUPolicy with AllowAll Action. Not policing.")
		return false
	}

	ip, ok := containerInfo.Runtime.DefaultIPAddress()
	if !ok || ip == "host" {
		log.WithFields(log.Fields{
			"package":   "trireme",
			"contextID": contextID,
		}).Debug("PUPolicy is in Host mode. Not policing")
		return false
	}

	return true
}

func (t *trireme) doHandleCreate(contextID string) error {

	// Retrieve the container runtime information from the cache
	cachedElement, err := t.cache.Get(contextID)
	if err != nil {
		log.WithFields(log.Fields{
			"package":   "trireme",
			"contextID": contextID,
			"error":     err.Error(),
		}).Debug("Cannot retrieve runtimeInfo from the cache")
		t.collector.CollectContainerEvent(contextID, "N/A", nil, collector.ContainerFailed)
		return fmt.Errorf("Couldn't get the runtimeInfo from the cache %s", err)
	}

	runtimeInfo := cachedElement.(*policy.PURuntime)

	policyInfo, err := t.resolver.ResolvePolicy(contextID, runtimeInfo)

	if err != nil {
		log.WithFields(log.Fields{
			"package":     "trireme",
			"contextID":   contextID,
			"runtimeInfo": runtimeInfo,
			"error":       err.Error(),
		}).Debug("Error returned when resolving the policy")
		t.collector.CollectContainerEvent(contextID, "N/A", nil, collector.ContainerFailed)
		return fmt.Errorf("Policy Error for this context: %s. Container killed. %s", contextID, err)
	}

	if policyInfo == nil {
		log.WithFields(log.Fields{
			"package":     "trireme",
			"contextID":   contextID,
			"runtimeInfo": runtimeInfo,
			"error":       err.Error(),
		}).Debug("Nil policy returned when resolving the context")
		t.collector.CollectContainerEvent(contextID, "N/A", nil, collector.ContainerFailed)
		return fmt.Errorf("Nil policy returned for context: %s. Container killed", contextID)
	}

	ip, _ := policyInfo.DefaultIPAddress()

	// Create a copy as we are going to modify it locally
	policyInfo = policyInfo.Clone()

	containerInfo := policy.PUInfoFromPolicyAndRuntime(contextID, policyInfo, runtimeInfo)

	addTransmitterLabel(contextID, containerInfo)

	if !mustEnforce(contextID, containerInfo) {
		t.collector.CollectContainerEvent(contextID, ip, containerInfo.Policy.Annotations(), collector.ContainerIgnored)
		return nil
	}

	if err := t.enforcers[containerInfo.Runtime.PUType()].Enforce(contextID, containerInfo); err != nil {

		log.WithFields(log.Fields{
			"package":   "trireme",
			"contextID": contextID,
			"error":     err.Error(),
		}).Debug("Not able to setup enforcer")
		t.collector.CollectContainerEvent(contextID, ip, policyInfo.Annotations(), collector.ContainerFailed)
		return fmt.Errorf("Not able to setup enforcer: %s", err)
	}

	if err := t.supervisors[containerInfo.Runtime.PUType()].Supervise(contextID, containerInfo); err != nil {
		t.enforcers[containerInfo.Runtime.PUType()].Unenforce(contextID)

		log.WithFields(log.Fields{
			"package":   "trireme",
			"contextID": contextID,
			"error":     err.Error(),
		}).Debug("Not able to setup supervisor")
		t.collector.CollectContainerEvent(contextID, ip, policyInfo.Annotations(), collector.ContainerFailed)
		return fmt.Errorf("Not able to setup supervisor: %s", err)
	}

	t.collector.CollectContainerEvent(contextID, ip, containerInfo.Policy.Annotations(), collector.ContainerStart)

	return nil
}

func (t *trireme) doHandleDelete(contextID string) error {
	log.WithFields(log.Fields{
		"package":   "trireme",
		"contextID": contextID,
	}).Debug("Started HandleDelete")

	runtime, err := t.PURuntime(contextID)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "trireme",
			"contextID": contextID,
			"error":     err.Error(),
		}).Debug("Error when getting runtime out of cache for ContextID")
		t.collector.CollectContainerEvent(contextID, "N/A", nil, collector.UnknownContainerDelete)
		return fmt.Errorf("Error getting Runtime out of cache for ContextID %s : %s", contextID, err)
	}

	ip, _ := runtime.DefaultIPAddress()

	errS := t.supervisors[runtime.PUType()].Unsupervise(contextID)
	errE := t.enforcers[runtime.PUType()].Unenforce(contextID)

	t.cache.Remove(contextID)

	if errS != nil || errE != nil {
		log.WithFields(log.Fields{
			"package":         "trireme",
			"contextID":       contextID,
			"supervisorError": errS,
			"enforcerError":   errE,
		}).Debug("Error when deleting")
		t.collector.CollectContainerEvent(contextID, ip, nil, collector.ContainerDelete)
		return fmt.Errorf("Delete Error for contextID %s. supervisor %s, enforcer %s", contextID, errS, errE)
	}

	t.collector.CollectContainerEvent(contextID, ip, nil, collector.ContainerDelete)
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

	log.WithFields(log.Fields{
		"package":   "trireme",
		"contextID": contextID,
	}).Debug("Start to update a policy")

	runtimeInfo, err := t.PURuntime(contextID)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "trireme",
			"contextID": contextID,
			"error":     err.Error(),
		}).Debug("Policy Update failed because couldn't find runtime for contextID")
		return fmt.Errorf("Policy Update failed because couldn't find runtime for contextID %s", contextID)
	}

	containerInfo := policy.PUInfoFromPolicyAndRuntime(contextID, newPolicy, runtimeInfo.(*policy.PURuntime))

	addTransmitterLabel(contextID, containerInfo)

	if !mustEnforce(contextID, containerInfo) {
		return nil
	}

	if err = t.enforcers[containerInfo.Runtime.PUType()].Enforce(contextID, containerInfo); err != nil {

		log.WithFields(log.Fields{
			"package":   "trireme",
			"contextID": contextID,
			"error":     err.Error(),
		}).Error("Policy Update failed for Enforcer")
		return fmt.Errorf("Policy Update failed for Enforcer %s", err)
	}

	if err = t.supervisors[containerInfo.Runtime.PUType()].Supervise(contextID, containerInfo); err != nil {
		t.enforcers[containerInfo.Runtime.PUType()].Unenforce(contextID)

		log.WithFields(log.Fields{
			"package":     "trireme",
			"trireme":     t,
			"contextID":   contextID,
			"policy":      newPolicy,
			"runtimeInfo": runtimeInfo,
			"error":       err,
		}).Error("Policy Update failed for Supervisor")
		return fmt.Errorf("Policy Update failed for Supervisor %s", err)
	}

	ip, _ := newPolicy.DefaultIPAddress()
	t.collector.CollectContainerEvent(contextID, ip, containerInfo.Runtime.Tags(), collector.ContainerUpdate)

	return nil
}

func (t *trireme) handleRequest(request *triremeRequest) error {
	switch request.reqType {
	case handleEvent:
		return t.doHandleEvent(request.contextID, request.eventType)
	case policyUpdate:
		return t.doUpdatePolicy(request.contextID, request.policyInfo)
	default:
		log.WithFields(log.Fields{
			"package": "trireme",
			"type":    request.reqType,
		}).Debug("Trireme Request format not recognized for the request")
		return fmt.Errorf("trireme Request format not recognized: %d", request.reqType)
	}
}

// Supervisor returns the Trireme supervisor for the given PU Type
func (t *trireme) Supervisor(kind constants.PUType) supervisor.Supervisor {

	if s, ok := t.supervisors[kind]; ok {
		return s
	}

	return nil
}

func (t *trireme) run() {
	for {
		select {
		case <-t.stop:
			log.WithFields(log.Fields{
				"package": "trireme",
			}).Debug("Stopping trireme worker.")
			return
		case req := <-t.requests:
			log.WithFields(log.Fields{
				"package":   "trireme",
				"type":      req.reqType,
				"contextID": req.contextID,
			}).Debug("Handling Trireme Request.")
			req.returnChan <- t.handleRequest(req)
		}
	}
}
