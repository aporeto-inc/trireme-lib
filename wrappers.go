package trireme

import (
	"fmt"

	"github.com/aporeto-inc/trireme-lib/internal/supervisor/proxy"

	"github.com/aporeto-inc/trireme-lib/enforcer"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/rpcwrapper"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/policyenforcer"
	"github.com/aporeto-inc/trireme-lib/enforcer/proxy"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/internal/monitor"
	"github.com/aporeto-inc/trireme-lib/internal/supervisor"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/rpc/events"
	"github.com/aporeto-inc/trireme-lib/utils/allocator"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
)

// trireme contains references to all the different components involved.
type trireme struct {
	config               *config
	cache                cache.DataStore
	supervisors          map[constants.ModeType]supervisor.Supervisor
	enforcers            map[constants.ModeType]policyenforcer.Enforcer
	puTypeToEnforcerType map[constants.PUType]constants.ModeType
	port                 allocator.Allocator
	rpchdl               rpcwrapper.RPCClient
	monitors             monitor.Monitor
}

func (t *trireme) newEnforcers() error {
	zap.L().Debug("LinuxProcessSupport", zap.Bool("Status", t.config.linuxProcess))
	if t.config.linuxProcess {
		t.enforcers[constants.LocalServer] = enforcer.New(
			t.config.mutualAuth,
			t.config.fq,
			t.config.collector,
			t.config.service,
			t.config.secret,
			t.config.serverID,
			t.config.validity,
			constants.LocalServer,
			t.config.procMountPoint,
			t.config.externalIPcacheTimeout,
			t.config.packetLogs,
		)
	}
	zap.L().Debug("TriremeMode", zap.Int("Status", int(t.config.mode)))
	if t.config.mode == constants.RemoteContainer {
		t.enforcers[constants.RemoteContainer] = enforcerproxy.NewProxyEnforcer(
			t.config.mutualAuth,
			t.config.fq,
			t.config.collector,
			t.config.service,
			t.config.secret,
			t.config.serverID,
			t.config.validity,
			t.rpchdl,
			"enforce",
			t.config.procMountPoint,
			t.config.externalIPcacheTimeout,
			t.config.packetLogs,
		)
	} else {
		t.enforcers[constants.LocalContainer] = enforcer.New(
			t.config.mutualAuth,
			t.config.fq,
			t.config.collector,
			t.config.service,
			t.config.secret,
			t.config.serverID,
			t.config.validity,
			constants.LocalServer,
			t.config.procMountPoint,
			t.config.externalIPcacheTimeout,
			t.config.packetLogs,
		)
	}

	return nil
}

func (t *trireme) newSupervisors() error {

	if t.config.linuxProcess {
		sup, err := supervisor.NewSupervisor(
			t.config.collector,
			t.enforcers[constants.LocalServer],
			constants.LocalServer,
			constants.IPTables,
			t.config.targetNetworks,
		)
		if err != nil {
			return fmt.Errorf("Could Not create process supervisor :: received error %v", err)
		}
		t.supervisors[constants.LocalServer] = sup
	}

	if t.config.mode == constants.RemoteContainer {
		s, err := supervisorproxy.NewProxySupervisor(
			t.config.collector,
			t.enforcers[constants.RemoteContainer],
			t.rpchdl,
		)
		if err != nil {
			zap.L().Error("Unable to create proxy Supervisor:: Returned Error ", zap.Error(err))
			return nil
		}
		t.supervisors[constants.RemoteContainer] = s
	} else {
		if _, ok := t.supervisors[constants.LocalServer]; ok {
			t.supervisors[constants.LocalContainer] = t.supervisors[constants.LocalServer]
		} else {
			sup, err := supervisor.NewSupervisor(
				t.config.collector,
				t.enforcers[constants.LocalContainer],
				constants.LocalContainer,
				constants.IPTables,
				t.config.targetNetworks,
			)
			if err != nil {
				return fmt.Errorf("Could Not create process supervisor :: received error %v", err)
			}
			t.supervisors[constants.LocalContainer] = sup
		}
	}

	return nil
}

// newTrireme returns a reference to the trireme object based on the parameter subelements.
func newTrireme(c *config) Trireme {

	var err error

	t := &trireme{
		config:               c,
		cache:                cache.NewCache("TriremeCache"),
		port:                 allocator.New(5000, 100),
		rpchdl:               rpcwrapper.NewRPCWrapper(),
		enforcers:            map[constants.ModeType]policyenforcer.Enforcer{},
		supervisors:          map[constants.ModeType]supervisor.Supervisor{},
		puTypeToEnforcerType: map[constants.PUType]constants.ModeType{},
	}

	zap.L().Debug("Creating Enforcers")
	if err = t.newEnforcers(); err != nil {
		zap.L().Error("Unable to create datapath enforcers", zap.Error(err))
		return nil
	}

	zap.L().Debug("Creating Supervisors")
	if err = t.newSupervisors(); err != nil {
		zap.L().Error("Unable to start datapath supervisor", zap.Error(err))
		return nil
	}

	if c.linuxProcess {
		t.puTypeToEnforcerType[constants.LinuxProcessPU] = constants.LocalServer
		t.puTypeToEnforcerType[constants.UIDLoginPU] = constants.LocalServer
	}

	if t.config.mode == constants.RemoteContainer {
		t.puTypeToEnforcerType[constants.ContainerPU] = constants.RemoteContainer
		t.puTypeToEnforcerType[constants.KubernetesPU] = constants.RemoteContainer
	} else {
		t.puTypeToEnforcerType[constants.ContainerPU] = constants.LocalContainer
		t.puTypeToEnforcerType[constants.KubernetesPU] = constants.LocalContainer
	}

	zap.L().Debug("Creating Monitors")
	if t.monitors, err = monitor.NewMonitors(c.collector, t, c.monitors); err != nil {
		zap.L().Error("Unable to start monitors", zap.Error(err))
		return nil
	}

	return t
}

// Start starts the supervisor and the enforcer. It will also start to handling requests
// For new PU Creation and Policy Updates.
func (t *trireme) Start() error {

	// Start all the supervisors.
	for _, s := range t.supervisors {
		if err := s.Start(); err != nil {
			zap.L().Error("Error when starting the supervisor", zap.Error(err))
			return fmt.Errorf("Error while starting supervisor %v", err)
		}
	}

	// Start all the enforcers.
	for _, e := range t.enforcers {
		if err := e.Start(); err != nil {
			return fmt.Errorf("unable to start the enforcer: %s", err)
		}
	}

	// Start monitors.
	if err := t.monitors.Start(); err != nil {
		return fmt.Errorf("unable to start monitors: %s", err)
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

	if err := t.monitors.Stop(); err != nil {
		zap.L().Error("Error when stopping the monitor", zap.Error(err))
	}

	return nil
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

// CreatePURuntime implements processor.ProcessingUnitsHandler
func (t *trireme) CreatePURuntime(contextID string, runtimeInfo *policy.PURuntime) error {

	if _, err := t.cache.Get(contextID); err == nil {
		return fmt.Errorf("pu %s already exists", contextID)
	}
	t.cache.AddOrUpdate(contextID, runtimeInfo)
	return nil
}

// HandlePUEvent implements processor.ProcessingUnitsHandler
func (t *trireme) HandlePUEvent(contextID string, event events.Event) error {

	// Notify The PolicyResolver that an event occurred:
	t.config.resolver.HandlePUEvent(contextID, event)

	switch event {
	case events.EventStart:
		return t.doHandleCreate(contextID)
	case events.EventStop:
		return t.doHandleDelete(contextID)
	default:
		return nil
	}
}

// addTransmitterLabel adds the enforcerconstants.TransmitterLabel as a fixed label in the policy.
// The ManagementID part of the policy is used as the enforcerconstants.TransmitterLabel.
// If the Policy didn't set the ManagementID, we use the Local contextID as the
// default enforcerconstants.TransmitterLabel.
func addTransmitterLabel(contextID string, containerInfo *policy.PUInfo) {

	if containerInfo.Policy.ManagementID() == "" {
		containerInfo.Policy.AddIdentityTag(enforcerconstants.TransmitterLabel, contextID)
	} else {
		containerInfo.Policy.AddIdentityTag(enforcerconstants.TransmitterLabel, containerInfo.Policy.ManagementID())
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

func (t *trireme) mergeRuntimeAndPolicy(r *policy.PURuntime, p *policy.PUPolicy) {

	if len(t.config.monitors.MergeTags) == 0 {
		return
	}

	tags := r.Tags()
	anno := p.Annotations()
	if tags == nil || anno == nil {
		return
	}

	for _, mt := range t.config.monitors.MergeTags {
		if _, ok := tags.Get(mt); !ok {
			if val, ok := anno.Get(mt); ok {
				tags.AppendKeyValue(mt, val)
			}
		}
	}

	r.SetTags(tags)
}

func (t *trireme) doHandleCreate(contextID string) error {

	// Retrieve the container runtime information from the cache
	cachedElement, err := t.cache.Get(contextID)
	if err != nil {
		t.config.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: "N/A",
			Tags:      nil,
			Event:     collector.ContainerFailed,
		})

		return fmt.Errorf("unable get the runtime info from the cache: %s", err)
	}

	runtimeInfo := cachedElement.(*policy.PURuntime)
	runtimeInfo.GlobalLock.Lock()
	defer runtimeInfo.GlobalLock.Unlock()

	policyInfo, err := t.config.resolver.ResolvePolicy(contextID, runtimeInfo)
	if err != nil || policyInfo == nil {
		t.config.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: "N/A",
			Tags:      nil,
			Event:     collector.ContainerFailed,
		})

		return fmt.Errorf("policy error for %s: %s", contextID, err)
	}

	t.mergeRuntimeAndPolicy(runtimeInfo, policyInfo)

	ip, _ := policyInfo.DefaultIPAddress()

	containerInfo := policy.PUInfoFromPolicyAndRuntime(contextID, policyInfo, runtimeInfo)
	newOptions := containerInfo.Runtime.Options()
	newOptions.ProxyPort = t.port.Allocate()

	containerInfo.Runtime.SetOptions(newOptions)

	addTransmitterLabel(contextID, containerInfo)
	if !mustEnforce(contextID, containerInfo) {
		t.config.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: ip,
			Tags:      policyInfo.Annotations(),
			Event:     collector.ContainerIgnored,
		})
		return nil
	}

	if err := t.enforcers[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].Enforce(contextID, containerInfo); err != nil {
		t.config.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: ip,
			Tags:      policyInfo.Annotations(),
			Event:     collector.ContainerFailed,
		})
		return fmt.Errorf("unable to setup enforcer: %s", err)
	}

	if err := t.supervisors[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].Supervise(contextID, containerInfo); err != nil {
		if werr := t.enforcers[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].Unenforce(contextID); werr != nil {
			zap.L().Warn("Failed to clean up state after failures",
				zap.String("contextID", contextID),
				zap.Error(werr),
			)
		}

		t.config.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: ip,
			Tags:      policyInfo.Annotations(),
			Event:     collector.ContainerFailed,
		})

		return fmt.Errorf("unable to setup supervisor: %s", err)
	}

	t.config.collector.CollectContainerEvent(&collector.ContainerRecord{
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
		t.config.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: "N/A",
			Tags:      nil,
			Event:     collector.ContainerDeleteUnknown,
		})
		return fmt.Errorf("unable to get runtime out of cache for context id %s: %s", contextID, err)
	}

	runtime := runtimeReader.(*policy.PURuntime)

	// Serialize operations
	runtime.GlobalLock.Lock()
	defer runtime.GlobalLock.Unlock()

	ip, _ := runtime.DefaultIPAddress()

	errS := t.supervisors[t.puTypeToEnforcerType[runtime.PUType()]].Unsupervise(contextID)
	errE := t.enforcers[t.puTypeToEnforcerType[runtime.PUType()]].Unenforce(contextID)
	port := runtime.Options().ProxyPort
	zap.L().Debug("Releasing Port", zap.String("Port", port))
	t.port.Release(port)
	if err := t.cache.Remove(contextID); err != nil {
		zap.L().Warn("Failed to remove context from cache during cleanup. Entry doesn't exist",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	if errS != nil || errE != nil {
		t.config.collector.CollectContainerEvent(&collector.ContainerRecord{
			ContextID: contextID,
			IPAddress: ip,
			Tags:      nil,
			Event:     collector.ContainerDelete,
		})

		return fmt.Errorf("unable to delete context id %s, supervisor %s, enforcer %s", contextID, errS, errE)
	}

	t.config.collector.CollectContainerEvent(&collector.ContainerRecord{
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
		return fmt.Errorf("policy update failed: runtime for context id %s not found", contextID)
	}

	runtime := runtimeReader.(*policy.PURuntime)
	// Serialize operations
	runtime.GlobalLock.Lock()
	defer runtime.GlobalLock.Unlock()
	_, err = t.PURuntime(contextID)
	if err != nil {
		zap.L().Error("PU Already Deleted do nothing", zap.String("contextID", contextID))
		return err
	}
	containerInfo := policy.PUInfoFromPolicyAndRuntime(contextID, newPolicy, runtime)

	addTransmitterLabel(contextID, containerInfo)

	if !mustEnforce(contextID, containerInfo) {
		return nil
	}

	if err = t.enforcers[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].Enforce(contextID, containerInfo); err != nil {
		//We lost communication with the remote and killed it lets restart it here by feeding a create event in the request channel
		zap.L().Warn("Re-initializing enforcers - connection lost")
		if containerInfo.Runtime.PUType() == constants.ContainerPU {
			//The unsupervise and unenforce functions just make changes to the proxy structures
			//and do not depend on the remote instance running and can be called here
			switch t.enforcers[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].(type) {
			case *enforcerproxy.ProxyInfo:
				if lerr := t.enforcers[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].Unenforce(contextID); lerr != nil {
					return err
				}

				if lerr := t.supervisors[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].Unsupervise(contextID); lerr != nil {
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

		return fmt.Errorf("enforcer failed to update policy for pu %s: %s", contextID, err)
	}

	if err = t.supervisors[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].Supervise(contextID, containerInfo); err != nil {
		if werr := t.enforcers[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].Unenforce(contextID); werr != nil {
			zap.L().Warn("Failed to clean up after enforcerments failures",
				zap.String("contextID", contextID),
				zap.Error(werr),
			)
		}
		return fmt.Errorf("supervisor failed to update policy for pu %s: %s", contextID, err)
	}

	ip, _ := newPolicy.DefaultIPAddress()
	t.config.collector.CollectContainerEvent(&collector.ContainerRecord{
		ContextID: contextID,
		IPAddress: ip,
		Tags:      containerInfo.Runtime.Tags(),
		Event:     collector.ContainerUpdate,
	})

	return nil
}

// Supervisor returns the Trireme supervisor for the given PU Type
func (t *trireme) Supervisor(kind constants.PUType) supervisor.Supervisor {

	if s, ok := t.supervisors[t.puTypeToEnforcerType[kind]]; ok {
		return s
	}
	return nil
}

func (t *trireme) UpdateSecrets(secrets secrets.Secrets) error {
	for _, enforcer := range t.enforcers {
		if err := enforcer.UpdateSecrets(secrets); err != nil {
			zap.L().Error("unable to update secrets", zap.Error(err))
		}
	}
	return nil
}

// Supervisors returns a slice of all initialized supervisors.
func Supervisors(t Trireme) []supervisor.Supervisor {

	supervisors := []supervisor.Supervisor{}

	// LinuxProcessPU, UIDLoginPU and HOstPU share the same supervisor so only one lookup suffices
	if s := t.Supervisor(constants.LinuxProcessPU); s != nil {
		supervisors = append(supervisors, s)
	}

	if s := t.Supervisor(constants.ContainerPU); s != nil {
		supervisors = append(supervisors, s)
	}
	return supervisors
}
