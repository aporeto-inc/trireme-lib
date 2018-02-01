package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/controller/constants"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/proxy"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/controller/internal/supervisor"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/utils/allocator"

	"go.uber.org/zap"
)

// trireme contains references to all the different components of the controller.
// Depending on the configuration we might have multiple supervisor and enforcer types.
// The initialization process must provide the mode that Trireme will run in.
type trireme struct {
	config               *config
	supervisors          map[constants.ModeType]supervisor.Supervisor
	enforcers            map[constants.ModeType]enforcer.Enforcer
	puTypeToEnforcerType map[common.PUType]constants.ModeType
	port                 allocator.Allocator
	rpchdl               rpcwrapper.RPCClient
}

// New returns a trireme interface implementation based on configuration provided.
func New(serverID string, opts ...Option) TriremeController {

	c := &config{
		serverID:               serverID,
		collector:              collector.NewDefaultCollector(),
		mode:                   constants.RemoteContainer,
		fq:                     fqconfig.NewFilterQueueWithDefaults(),
		mutualAuth:             true,
		validity:               time.Hour * 8760,
		procMountPoint:         constants.DefaultProcMountPoint,
		externalIPcacheTimeout: -1,
	}

	for _, opt := range opts {
		opt(c)
	}

	zap.L().Debug("Trireme configuration", zap.String("configuration", fmt.Sprintf("%+v", c)))

	return newTrireme(c)
}

// Run starts the supervisor and the enforcer and go routines. It doesn't try to clean
// up if something went wrong. It will be up to the caller to decide what to do.
func (t *trireme) Run(ctx context.Context) error {

	// Start all the supervisors.
	for _, s := range t.supervisors {
		if err := s.Run(ctx); err != nil {
			zap.L().Error("Error when starting the supervisor", zap.Error(err))
			return fmt.Errorf("Error while starting supervisor %v", err)
		}
	}

	// Start all the enforcers.
	for _, e := range t.enforcers {
		if err := e.Run(ctx); err != nil {
			return fmt.Errorf("unable to start the enforcer: %s", err)
		}
	}

	return nil
}

// UpdatePolicy updates a policy for an already activated PU. The PU is identified by the contextID
func (t *trireme) UpdatePolicy(contextID string, plc *policy.PUPolicy, runtime *policy.PURuntime) error {

	return t.doUpdatePolicy(contextID, plc, runtime)
}

// HandlePUEvent implements processor.ProcessingUnitsHandler
func (t *trireme) ProcessEvent(ctx context.Context, event common.Event, contextID string, policy *policy.PUPolicy, runtime *policy.PURuntime) (err error) {

	switch event {
	case common.EventStart:
		return t.doHandleCreate(contextID, policy, runtime)
	case common.EventStop:
		return t.doHandleDelete(contextID, policy, runtime)
	default:
		return nil
	}
}

// UpdateSecrets updates the secrets of the controllers.
func (t *trireme) UpdateSecrets(secrets secrets.Secrets) error {
	for _, enforcer := range t.enforcers {
		if err := enforcer.UpdateSecrets(secrets); err != nil {
			zap.L().Error("unable to update secrets", zap.Error(err))
		}
	}
	return nil
}

// UpdateConfiguration updates the configuration of the controller. Only
// a limited number of parameters can be updated at run time.
func (t *trireme) UpdateConfiguration(networks []string) error {

	failure := false

	for _, s := range t.supervisors {
		err := s.SetTargetNetworks(networks)
		if err != nil {
			zap.L().Error("Failed to update target networks in supervisor")
			failure = true
		}
	}

	if failure {
		return fmt.Errorf("Configuration update failed")
	}

	return nil
}

// doHandleCreate is the detailed implementation of the create event.
func (t *trireme) doHandleCreate(contextID string, policyInfo *policy.PUPolicy, runtimeInfo *policy.PURuntime) error {

	runtimeInfo.GlobalLock.Lock()
	defer runtimeInfo.GlobalLock.Unlock()

	containerInfo := policy.PUInfoFromPolicyAndRuntime(contextID, policyInfo, runtimeInfo)
	newOptions := containerInfo.Runtime.Options()
	newOptions.ProxyPort = t.port.Allocate()
	containerInfo.Runtime.SetOptions(newOptions)

	logEvent := &collector.ContainerRecord{
		ContextID: contextID,
		IPAddress: runtimeInfo.IPAddresses(),
		Tags:      policyInfo.Annotations(),
		Event:     collector.ContainerStart,
	}

	defer t.config.collector.CollectContainerEvent(logEvent)

	addTransmitterLabel(contextID, containerInfo)
	if !mustEnforce(contextID, containerInfo) {
		logEvent.Event = collector.ContainerIgnored
		return nil
	}

	if err := t.enforcers[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].Enforce(contextID, containerInfo); err != nil {
		logEvent.Event = collector.ContainerFailed
		return fmt.Errorf("unable to setup enforcer: %s", err)
	}

	if err := t.supervisors[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].Supervise(contextID, containerInfo); err != nil {
		if werr := t.enforcers[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].Unenforce(contextID); werr != nil {
			zap.L().Warn("Failed to clean up state after failures",
				zap.String("contextID", contextID),
				zap.Error(werr),
			)
		}

		logEvent.Event = collector.ContainerFailed
		return fmt.Errorf("unable to setup supervisor: %s", err)
	}

	return nil
}

// doHandleDelete is the detailed implementation of the delete event.
func (t *trireme) doHandleDelete(contextID string, policy *policy.PUPolicy, runtime *policy.PURuntime) error {

	// Serialize operations
	runtime.GlobalLock.Lock()
	defer runtime.GlobalLock.Unlock()

	t.config.collector.CollectContainerEvent(&collector.ContainerRecord{
		ContextID: contextID,
		IPAddress: runtime.IPAddresses(),
		Tags:      nil,
		Event:     collector.ContainerDelete,
	})

	errS := t.supervisors[t.puTypeToEnforcerType[runtime.PUType()]].Unsupervise(contextID)
	errE := t.enforcers[t.puTypeToEnforcerType[runtime.PUType()]].Unenforce(contextID)
	t.port.Release(runtime.Options().ProxyPort)

	if errS != nil || errE != nil {
		return fmt.Errorf("unable to delete context id %s, supervisor %s, enforcer %s", contextID, errS, errE)
	}

	return nil
}

// doUpdatePolicy is the detailed implementation of the update policy event.
func (t *trireme) doUpdatePolicy(contextID string, newPolicy *policy.PUPolicy, runtime *policy.PURuntime) error {

	// Serialize operations
	runtime.GlobalLock.Lock()
	defer runtime.GlobalLock.Unlock()

	containerInfo := policy.PUInfoFromPolicyAndRuntime(contextID, newPolicy, runtime)

	addTransmitterLabel(contextID, containerInfo)

	if !mustEnforce(contextID, containerInfo) {
		return nil
	}

	if err := t.enforcers[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].Enforce(contextID, containerInfo); err != nil {
		//We lost communication with the remote and killed it lets restart it here by feeding a create event in the request channel
		zap.L().Warn("Re-initializing enforcers - connection lost")
		if containerInfo.Runtime.PUType() == common.ContainerPU {
			//The unsupervise and unenforce functions just make changes to the proxy structures
			//and do not depend on the remote instance running and can be called here
			switch t.enforcers[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].(type) {
			case *enforcerproxy.ProxyInfo:
				if lerr := t.enforcers[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].Unenforce(contextID); lerr != nil {
					return lerr
				}

				if lerr := t.supervisors[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].Unsupervise(contextID); lerr != nil {
					return lerr
				}

				if lerr := t.doHandleCreate(contextID, newPolicy, runtime); lerr != nil {
					return err
				}
			default:
				return err
			}
			return nil
		}

		return fmt.Errorf("enforcer failed to update policy for pu %s: %s", contextID, err)
	}

	if err := t.supervisors[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].Supervise(contextID, containerInfo); err != nil {
		if werr := t.enforcers[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].Unenforce(contextID); werr != nil {
			zap.L().Warn("Failed to clean up after enforcerments failures",
				zap.String("contextID", contextID),
				zap.Error(werr),
			)
		}
		return fmt.Errorf("supervisor failed to update policy for pu %s: %s", contextID, err)
	}

	t.config.collector.CollectContainerEvent(&collector.ContainerRecord{
		ContextID: contextID,
		IPAddress: runtime.IPAddresses(),
		Tags:      containerInfo.Runtime.Tags(),
		Event:     collector.ContainerUpdate,
	})

	return nil
}
