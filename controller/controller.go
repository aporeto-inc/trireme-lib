package controller

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/trireme-lib/controller/internal/supervisor"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/controller/pkg/dmesgparser"
	"go.aporeto.io/trireme-lib/controller/pkg/env"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/packettracing"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

type traceTrigger struct {
	duration time.Duration
	expiry   time.Time
}

// trireme contains references to all the different components of the controller.
// Depending on the configuration we might have multiple supervisor and enforcer types.
// The initialization process must provide the mode that Trireme will run in.
type trireme struct {
	config               *config
	supervisors          map[constants.ModeType]supervisor.Supervisor
	enforcers            map[constants.ModeType]enforcer.Enforcer
	puTypeToEnforcerType map[common.PUType]constants.ModeType
	enablingTrace        chan *traceTrigger
	locks                sync.Map
}

// New returns a trireme interface implementation based on configuration provided.
func New(serverID string, mode constants.ModeType, opts ...Option) TriremeController {

	c := &config{
		serverID:               serverID,
		collector:              collector.NewDefaultCollector(),
		mode:                   mode,
		fq:                     fqconfig.NewFilterQueueWithDefaults(),
		mutualAuth:             true,
		validity:               time.Hour * 8760,
		procMountPoint:         constants.DefaultProcMountPoint,
		externalIPcacheTimeout: -1,
		remoteParameters: &env.RemoteParameters{
			LogToConsole:   true,
			LogFormat:      "console",
			LogLevel:       "info",
			LogWithID:      false,
			CompressedTags: claimsheader.CompressionTypeV1,
		},
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
	go t.runIPTraceCollector(ctx)
	return nil
}

// CleanUp cleans all the acls and all the remote supervisors
func (t *trireme) CleanUp() error {
	for _, s := range t.supervisors {
		s.CleanUp() // nolint
	}

	for _, e := range t.enforcers {
		e.CleanUp() // nolint
	}
	return nil
}

// Enforce asks the controller to enforce policy to a processing unit
func (t *trireme) Enforce(ctx context.Context, puID string, policy *policy.PUPolicy, runtime *policy.PURuntime) error {
	lock, _ := t.locks.LoadOrStore(puID, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()
	return t.doHandleCreate(puID, policy, runtime)
}

// Enforce asks the controller to enforce policy to a processing unit
func (t *trireme) UnEnforce(ctx context.Context, puID string, policy *policy.PUPolicy, runtime *policy.PURuntime) error {
	lock, _ := t.locks.LoadOrStore(puID, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer func() {
		t.locks.Delete(puID)
		lock.(*sync.Mutex).Unlock()
	}()
	return t.doHandleDelete(puID, runtime)
}

// UpdatePolicy updates a policy for an already activated PU. The PU is identified by the contextID
func (t *trireme) UpdatePolicy(ctx context.Context, puID string, plc *policy.PUPolicy, runtime *policy.PURuntime) error {
	lock, ok := t.locks.Load(puID)
	if !ok {
		return nil
	}

	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()
	return t.doUpdatePolicy(puID, plc, runtime)
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
func (t *trireme) UpdateConfiguration(cfg *runtime.Configuration) error {

	failure := false

	for _, s := range t.supervisors {
		err := s.SetTargetNetworks(cfg)
		if err != nil {
			zap.L().Error("Failed to update target networks in supervisor", zap.Error(err))
			failure = true
		}
	}

	for _, e := range t.enforcers {
		err := e.SetTargetNetworks(cfg)
		if err != nil {
			zap.L().Error("Failed to update target networks in cotnroller", zap.Error(err))
			failure = true
		}
	}

	if failure {
		return fmt.Errorf("configuration update failed")
	}

	return nil
}

// doHandleCreate is the detailed implementation of the create event.
func (t *trireme) doHandleCreate(contextID string, policyInfo *policy.PUPolicy, runtimeInfo *policy.PURuntime) error {

	containerInfo := policy.PUInfoFromPolicyAndRuntime(contextID, policyInfo, runtimeInfo)

	logEvent := &collector.ContainerRecord{
		ContextID: contextID,
		IPAddress: policyInfo.IPAddresses(),
		Tags:      policyInfo.Annotations(),
		Event:     collector.ContainerStart,
	}

	defer func() {
		t.config.collector.CollectContainerEvent(logEvent)
	}()

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
func (t *trireme) doHandleDelete(contextID string, runtime *policy.PURuntime) error {

	errS := t.supervisors[t.puTypeToEnforcerType[runtime.PUType()]].Unsupervise(contextID)
	errE := t.enforcers[t.puTypeToEnforcerType[runtime.PUType()]].Unenforce(contextID)

	t.config.collector.CollectContainerEvent(&collector.ContainerRecord{
		ContextID: contextID,
		IPAddress: runtime.IPAddresses(),
		Tags:      nil,
		Event:     collector.ContainerDelete,
	})

	if errS != nil || errE != nil {
		return fmt.Errorf("unable to delete context id %s, supervisor %s, enforcer %s", contextID, errS, errE)
	}

	return nil
}

// doUpdatePolicy is the detailed implementation of the update policy event.
func (t *trireme) doUpdatePolicy(contextID string, newPolicy *policy.PUPolicy, runtime *policy.PURuntime) error {

	containerInfo := policy.PUInfoFromPolicyAndRuntime(contextID, newPolicy, runtime)

	addTransmitterLabel(contextID, containerInfo)

	if !mustEnforce(contextID, containerInfo) {
		return nil
	}

	if err := t.enforcers[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].Enforce(contextID, containerInfo); err != nil {
		//We lost communication with the remote and killed it lets restart it here by feeding a create event in the request channel
		if werr := t.supervisors[t.puTypeToEnforcerType[containerInfo.Runtime.PUType()]].Unsupervise(contextID); werr != nil {
			zap.L().Warn("Failed to clean up after enforcerments failures",
				zap.String("contextID", contextID),
				zap.Error(werr),
			)
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

//Debug Handlers
func (t *trireme) EnableDatapathPacketTracing(contextID string, direction packettracing.TracingDirection, interval time.Duration, putype common.PUType) error {
	return t.enforcers[t.puTypeToEnforcerType[putype]].EnableDatapathPacketTracing(contextID, direction, interval)
}

func (t *trireme) EnableIPTablesPacketTracing(ctx context.Context, contextID string, interval time.Duration, putype common.PUType) error {

	sysctlCmd, err := exec.LookPath("sysctl")
	if err != nil {
		return fmt.Errorf("sysctl command not found")
	}

	cmd := exec.Command(sysctlCmd, "-w", "net.netfilter.nf_log_all_netns=1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("remote container iptables tracing will not work %s", err)
	}

	t.enablingTrace <- &traceTrigger{
		duration: interval,
		expiry:   time.Now().Add(interval),
	}

	if err := t.supervisors[t.puTypeToEnforcerType[putype]].EnableIPTablesPacketTracing(ctx, contextID, interval); err != nil {
		return err
	}

	return t.enforcers[t.puTypeToEnforcerType[putype]].EnableIPTablesPacketTracing(ctx, contextID, interval)
}

func (t *trireme) runIPTraceCollector(ctx context.Context) {
	//Run dmesg once to establish baseline
	expiry := time.Now()
	hdl := dmesgparser.New()
	for {
		select {
		case <-ctx.Done():
			return
		case traceparams := <-t.enablingTrace:
			if !traceparams.expiry.After(expiry) {
				//if we already have a request expiring later drop this
				continue
			}

			expiry = traceparams.expiry
		case <-time.After(1 * time.Second):
			if !time.Now().After(expiry) {
				messages, err := hdl.RunDmesgCommand()
				if err != nil {
					zap.L().Warn("Unable to run dmesg", zap.Error(err))
					continue
				}
				t.config.collector.CollectTraceEvent(messages)

			}
		}
	}

}
