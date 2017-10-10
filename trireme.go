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
	"github.com/aporeto-inc/trireme/monitor/portmap"
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
	port        *portmap.ProxyPortMap
}

// NewTrireme returns a reference to the trireme object based on the parameter subelements.
func NewTrireme(serverID string, resolver PolicyResolver, supervisors map[constants.PUType]supervisor.Supervisor, enforcers map[constants.PUType]enforcer.PolicyEnforcer, eventCollector collector.EventCollector) Trireme {

	t := &trireme{
		serverID:    serverID,
		cache:       cache.NewCache(),
		supervisors: supervisors,
		enforcers:   enforcers,
		resolver:    resolver,
		collector:   eventCollector,
		port:        portmap.New(5000, 100),
	}

	return t
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

	return nil
}

// HandlePUEvent implements the logic needed between all the Trireme components for
// explicitly adding a new PU.
func (t *trireme) HandlePUEvent(contextID string, event monitor.Event) error {

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

// UpdatePolicy updates a policy for an already activated PU. The PU is identified by the contextID
func (t *trireme) UpdatePolicy(contextID string, newPolicy *policy.PUPolicy) error {

	return t.doUpdatePolicy(contextID, newPolicy)
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

	if _, err := t.cache.Get(contextID); err == nil {
		return fmt.Errorf("PU Exists Already")
	}

	t.cache.AddOrUpdate(contextID, runtimeInfo)

	return nil

}

// addTransmitterLabel adds the TransmitterLabel as a fixed label in the policy.
// The ManagementID part of the policy is used as the TransmitterLabel.
// If the Policy didn't set the ManagementID, we use the Local contextID as the
// default TransmitterLabel.
func addTransmitterLabel(contextID string, containerInfo *policy.PUInfo) {

	if containerInfo.Policy.ManagementID() == "" {
		containerInfo.Policy.AddIdentityTag(enforcer.TransmitterLabel, contextID)
	} else {
		containerInfo.Policy.AddIdentityTag(enforcer.TransmitterLabel, containerInfo.Policy.ManagementID())
	}
}

// MustEnforce returns true if the Policy should go Through the Enforcer/Supervisor.
// Return false if:
//   - PU is in host namespace.
//   - Policy got the AllowAll tag.
func mustEnforce(contextID string, containerInfo *policy.PUInfo) bool {

	if containerInfo.Policy.TriremeAction() == policy.AllowAll {
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
	runtimeInfo.GlobalLock.Lock()
	defer runtimeInfo.GlobalLock.Unlock()

	policyInfo, err := t.resolver.ResolvePolicy(contextID, runtimeInfo)

	if err != nil || policyInfo == nil {
		t.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: "N/A",
			Tags:      nil,
			Event:     collector.ContainerFailed,
		})

		return fmt.Errorf("Policy Error for this context: %s. Container killed. %s", contextID, err)
	}

	ip, _ := policyInfo.DefaultIPAddress()

	containerInfo := policy.PUInfoFromPolicyAndRuntime(contextID, policyInfo, runtimeInfo)
	newOptions := containerInfo.Runtime.Options()
	newOptions.ProxyPort = t.port.GetPort()
	containerInfo.Runtime.SetOptions(newOptions)

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

	runtimeReader, err := t.PURuntime(contextID)
	if err != nil {
		t.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: "N/A",
			Tags:      nil,
			Event:     collector.UnknownContainerDelete,
		})
		return fmt.Errorf("Error getting Runtime out of cache for ContextID %s: %s", contextID, err)
	}

	runtime := runtimeReader.(*policy.PURuntime)

	// Serialize operations
	runtime.GlobalLock.Lock()
	defer runtime.GlobalLock.Unlock()

	ip, _ := runtime.DefaultIPAddress()

	errS := t.supervisors[runtime.PUType()].Unsupervise(contextID)
	errE := t.enforcers[runtime.PUType()].Unenforce(contextID)
	port := runtime.Options().ProxyPort
	zap.L().Info("Releasing Port", zap.String("Port", port))
	t.port.ReleasePort(port)
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

func (t *trireme) doUpdatePolicy(contextID string, newPolicy *policy.PUPolicy) error {

	runtimeReader, err := t.PURuntime(contextID)
	if err != nil {
		return fmt.Errorf("Policy Update failed because couldn't find runtime for contextID %s", contextID)
	}

	runtime := runtimeReader.(*policy.PURuntime)
	// Serialize operations
	runtime.GlobalLock.Lock()
	defer runtime.GlobalLock.Unlock()

	containerInfo := policy.PUInfoFromPolicyAndRuntime(contextID, newPolicy, runtime)

	addTransmitterLabel(contextID, containerInfo)

	if !mustEnforce(contextID, containerInfo) {
		return nil
	}

	if err = t.enforcers[containerInfo.Runtime.PUType()].Enforce(contextID, containerInfo); err != nil {
		//We lost communication with the remote and killed it lets restart it here by feeding a create event in the request channel
		zap.L().Warn("Re-initializing enforcers - connection lost")
		if containerInfo.Runtime.PUType() == constants.ContainerPU {
			//The unsupervise and unenforce functions just make changes to the proxy structures
			//and do not depend on the remote instance running and can be called here
			switch t.enforcers[containerInfo.Runtime.PUType()].(type) {
			case *enforcerproxy.ProxyInfo:
				if lerr := t.enforcers[containerInfo.Runtime.PUType()].Unenforce(contextID); lerr != nil {
					return err
				}

				if lerr := t.supervisors[containerInfo.Runtime.PUType()].Unsupervise(contextID); lerr != nil {
					return err
				}

				if lerr := t.doHandleCreate(contextID); lerr != nil {
					return err
				}
			default:
				return err
			}
			return nil
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

// Supervisor returns the Trireme supervisor for the given PU Type
func (t *trireme) Supervisor(kind constants.PUType) supervisor.Supervisor {

	if s, ok := t.supervisors[kind]; ok {
		return s
	}
	return nil
}
