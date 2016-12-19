package trireme

import (
	"fmt"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor"

	log "github.com/Sirupsen/logrus"
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

	return trireme
}

// Start starts the supervisor and the enforcer. It will also start to handling requests
// For new PU Creation and Policy Updates.
func (t *trireme) Start() error {

	if err := t.supervisor.Start(); err != nil {
		log.WithFields(log.Fields{
			"package": "trireme",
			"error":   err.Error(),
		}).Debug("Error when starting the controller")
		return fmt.Errorf("Error starting Controller: %s", err)
	}

	if err := t.enforcer.Start(); err != nil {
		log.WithFields(log.Fields{
			"package": "trireme",
			"error":   err.Error(),
		}).Debug("Error when starting the enforcer")
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
		log.WithFields(log.Fields{
			"package": "trireme",
			"error":   err.Error(),
		}).Debug("Error when stopping the controller")
		return fmt.Errorf("Error stopping Controller: %s", err)
	}

	if err := t.enforcer.Stop(); err != nil {
		log.WithFields(log.Fields{
			"package": "trireme",
			"error":   err.Error(),
		}).Debug("Error when stopping the enforcer")
		return fmt.Errorf("Error stopping enforcer: %s", err)
	}

	return nil
}

// HandleCreate implements the logic needed between all the Trireme components for
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

func (t *trireme) doHandleCreate(contextID string) error {

	log.WithFields(log.Fields{
		"package":   "trireme",
		"contextID": contextID,
	}).Debug("Started HandleCreate")

	// Cache all the container runtime information
	cachedElement, err := t.cache.Get(contextID)
	if err != nil {
		log.WithFields(log.Fields{
			"package":   "trireme",
			"contextID": contextID,
			"error":     err.Error(),
		}).Debug("Couldn't add the runtimeInfo to the cache")

		return fmt.Errorf("Couldn't add the runtimeInfo to the cache %s", err)
	}

	runtimeInfo := cachedElement.(*policy.PURuntime)
	policyInfo, err := t.resolver.ResolvePolicy(contextID, runtimeInfo)

	if err != nil {
		log.WithFields(log.Fields{
			"package":     "trireme",
			"contextID":   contextID,
			"runtimeInfo": runtimeInfo,
			"error":       err.Error(),
		}).Debug("Error returned when resolving the context")
		return fmt.Errorf("Policy Error for this context: %s. Container killed. %s", contextID, err)
	}

	if policyInfo == nil {
		log.WithFields(log.Fields{
			"package":     "trireme",
			"contextID":   contextID,
			"runtimeInfo": runtimeInfo,
			"error":       err.Error(),
		}).Debug("Nil policy returned when resolving the context")

		return fmt.Errorf("Nil policy returned for context: %s. Container killed", contextID)
	}

	// Create a copy as we are going to modify it locally
	policyInfo = policyInfo.Clone()

	containerInfo := policy.PUInfoFromPolicyAndRuntime(contextID, policyInfo, runtimeInfo)

	addTransmitterLabel(contextID, containerInfo)

	err = t.supervisor.Supervise(contextID, containerInfo)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "trireme",
			"contextID": contextID,
			"error":     err.Error(),
		}).Debug("Not able to setup supervisor")

		return fmt.Errorf("Not able to setup supervisor: %s", err)
	}

	err = t.enforcer.Enforce(contextID, containerInfo)

	if err != nil {
		t.supervisor.Unsupervise(contextID)

		log.WithFields(log.Fields{
			"package":   "trireme",
			"contextID": contextID,
			"error":     err.Error(),
		}).Debug("Not able to setup enforcer")

		return fmt.Errorf("Not able to setup enforcer: %s", err)
	}

	log.WithFields(log.Fields{
		"package":   "trireme",
		"contextID": contextID,
	}).Debug("Finished HandleCreate")

	return nil
}

func (t *trireme) doHandleDelete(contextID string) error {
	log.WithFields(log.Fields{
		"package":   "trireme",
		"contextID": contextID,
	}).Debug("Started HandleDelete")

	_, err := t.PURuntime(contextID)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "trireme",
			"contextID": contextID,
			"error":     err.Error(),
		}).Debug("Error when getting runtime out of cache for ContextID")

		return fmt.Errorf("Error getting Runtime out of cache for ContextID %s : %s", contextID, err)
	}

	errS := t.supervisor.Unsupervise(contextID)
	errE := t.enforcer.Unenforce(contextID)
	t.cache.Remove(contextID)

	if errS != nil || errE != nil {
		log.WithFields(log.Fields{
			"package":         "trireme",
			"contextID":       contextID,
			"supervisorError": errS.Error(),
			"enforcerError":   errE.Error(),
		}).Debug("Error when deleting")

		return fmt.Errorf("Delete Error for contextID %s. supervisor %s, enforcer %s", contextID, errS, errE)
	}

	log.WithFields(log.Fields{
		"package":   "trireme",
		"contextID": contextID,
	}).Debug("Finished HandleDelete")

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
	}
	return nil
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

	err = t.supervisor.Supervise(contextID, containerInfo)

	if err != nil {
		log.WithFields(log.Fields{
			"package":   "trireme",
			"contextID": contextID,
			"error":     err.Error(),
		}).Error("Policy Update failed for Supervisor")
		return fmt.Errorf("Policy Update failed for Supervisor %s", err)
	}

	err = t.enforcer.Enforce(contextID, containerInfo)

	if err != nil {
		t.supervisor.Unsupervise(contextID)
		log.WithFields(log.Fields{
			"package":   "trireme",
			"contextID": contextID,
			"error":     err.Error(),
		}).Error("Policy Update failed for Enforcer")
		return fmt.Errorf("Policy Update failed for Enforcer %s", err)
	}

	log.WithFields(log.Fields{
		"package":   "trireme",
		"contextID": contextID,
	}).Debug("Finish to update a policy")

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
