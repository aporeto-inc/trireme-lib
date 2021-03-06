package controller

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/supervisor"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/dmesgparser"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/env"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packettracing"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/controller/runtime"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
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
func New(ctx context.Context, serverID string, mode constants.ModeType, opts ...Option) TriremeController {

	c := &config{
		serverID:               serverID,
		collector:              collector.NewDefaultCollector(),
		mode:                   mode,
		mutualAuth:             true,
		validity:               constants.SynTokenValidity,
		procMountPoint:         constants.DefaultProcMountPoint,
		externalIPcacheTimeout: -1,
		remoteParameters: &env.RemoteParameters{
			LogFormat:      "console",
			LogWithID:      false,
			CompressedTags: claimsheader.CompressionTypeV1,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	zap.L().Debug("Trireme configuration", zap.String("configuration", fmt.Sprintf("%+v", c)))

	return newTrireme(ctx, c)
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
	return t.doHandleCreate(ctx, puID, policy, runtime)
}

// Enforce asks the controller to enforce policy to a processing unit
func (t *trireme) UnEnforce(ctx context.Context, puID string, policy *policy.PUPolicy, runtime *policy.PURuntime) error {
	lock, _ := t.locks.LoadOrStore(puID, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer func() {
		t.locks.Delete(puID)
		lock.(*sync.Mutex).Unlock()
	}()
	return t.doHandleDelete(ctx, puID, policy, runtime)
}

// UpdatePolicy updates a policy for an already activated PU. The PU is identified by the contextID
func (t *trireme) UpdatePolicy(ctx context.Context, puID string, plc *policy.PUPolicy, runtime *policy.PURuntime) error {
	lock, _ := t.locks.LoadOrStore(puID, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()
	return t.doUpdatePolicy(ctx, puID, plc, runtime)
}

func (t *trireme) EnableDatapathPacketTracing(ctx context.Context, puID string, policy *policy.PUPolicy, runtime *policy.PURuntime, direction packettracing.TracingDirection, interval time.Duration) error {
	lock, _ := t.locks.LoadOrStore(puID, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()
	return t.doHandleEnableDatapathPacketTracing(ctx, puID, policy, runtime, direction, interval)
}

func (t *trireme) EnableIPTablesPacketTracing(ctx context.Context, puID string, policy *policy.PUPolicy, runtime *policy.PURuntime, interval time.Duration) error {
	lock, _ := t.locks.LoadOrStore(puID, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()
	return t.doHandleEnableIPTablesPacketTracing(ctx, puID, policy, runtime, interval)
}

// Ping runs ping based on the given config.
func (t *trireme) Ping(ctx context.Context, puID string, policy *policy.PUPolicy, runtime *policy.PURuntime, pingConfig *policy.PingConfig) error {
	lock, _ := t.locks.LoadOrStore(puID, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()
	return t.enforcers[t.modeTypeFromPolicy(policy, runtime)].Ping(ctx, puID, pingConfig)
}

func (t *trireme) DebugCollect(ctx context.Context, puID string, policy *policy.PUPolicy, runtime *policy.PURuntime, debugConfig *policy.DebugConfig) error {
	lock, _ := t.locks.LoadOrStore(puID, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()
	return t.enforcers[t.modeTypeFromPolicy(policy, runtime)].DebugCollect(ctx, puID, debugConfig)
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
		if cfg.LogLevel != "" {
			if err := e.SetLogLevel(cfg.LogLevel); err != nil {
				zap.L().Error("unable to set log level", zap.Error(err))
			}
		}

		err := e.SetTargetNetworks(cfg)
		if err != nil {
			zap.L().Error("Failed to update target networks in controller", zap.Error(err))
			failure = true
		}
	}

	if failure {
		return fmt.Errorf("configuration update failed")
	}

	return nil
}

// doHandleCreate is the detailed implementation of the create event.
func (t *trireme) doHandleCreate(ctx context.Context, contextID string, policyInfo *policy.PUPolicy, runtimeInfo *policy.PURuntime) error {

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

	modeType := t.modeTypeFromPolicy(containerInfo.Policy, containerInfo.Runtime)

	if err := t.enforcers[modeType].Enforce(ctx, contextID, containerInfo); err != nil {
		logEvent.Event = collector.ContainerFailed
		return fmt.Errorf("unable to setup enforcer: %s", err)
	}

	if err := t.supervisors[modeType].Supervise(contextID, containerInfo); err != nil {
		if werr := t.enforcers[modeType].Unenforce(ctx, contextID); werr != nil {
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
func (t *trireme) doHandleDelete(ctx context.Context, contextID string, policyInfo *policy.PUPolicy, runtime *policy.PURuntime) error {

	modeType := t.modeTypeFromPolicy(policyInfo, runtime)

	errS := t.supervisors[modeType].Unsupervise(contextID)
	errE := t.enforcers[modeType].Unenforce(ctx, contextID)

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
func (t *trireme) doUpdatePolicy(ctx context.Context, contextID string, newPolicy *policy.PUPolicy, runtime *policy.PURuntime) error {

	containerInfo := policy.PUInfoFromPolicyAndRuntime(contextID, newPolicy, runtime)

	addTransmitterLabel(contextID, containerInfo)

	if !mustEnforce(contextID, containerInfo) {
		return nil
	}

	modeType := t.modeTypeFromPolicy(containerInfo.Policy, containerInfo.Runtime)

	if err := t.enforcers[modeType].Enforce(ctx, contextID, containerInfo); err != nil {
		//We lost communication with the remote and killed it lets restart it here by feeding a create event in the request channel
		if werr := t.supervisors[modeType].Unsupervise(contextID); werr != nil {
			zap.L().Warn("Failed to clean up after enforcerments failures",
				zap.String("contextID", contextID),
				zap.Error(werr),
			)
		}
		return fmt.Errorf("unable to update policy for pu %s: %s", contextID, err)
	}

	if err := t.supervisors[modeType].Supervise(contextID, containerInfo); err != nil {
		if werr := t.enforcers[modeType].Unenforce(ctx, contextID); werr != nil {
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
func (t *trireme) doHandleEnableDatapathPacketTracing(ctx context.Context, puID string, policy *policy.PUPolicy, runtime *policy.PURuntime, direction packettracing.TracingDirection, interval time.Duration) error {

	return t.enforcers[t.modeTypeFromPolicy(policy, runtime)].EnableDatapathPacketTracing(ctx, puID, direction, interval)
}

func (t *trireme) doHandleEnableIPTablesPacketTracing(ctx context.Context, puID string, policy *policy.PUPolicy, runtime *policy.PURuntime, interval time.Duration) error {

	modeType := t.modeTypeFromPolicy(policy, runtime)

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

	if err := t.supervisors[modeType].EnableIPTablesPacketTracing(ctx, puID, interval); err != nil {
		return err
	}

	return t.enforcers[modeType].EnableIPTablesPacketTracing(ctx, puID, interval)
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

func (t *trireme) modeTypeFromPolicy(policyInfo *policy.PUPolicy, runtime *policy.PURuntime) constants.ModeType {
	if policyInfo == nil {
		// there are edge cases when policyInfo really can be nil - and it is fine
		// let's just fall back to the normal enforcertype mapping if this is the case
		//
		// Here is an example: when a PU Create event failed, but the PU gets destroyed afterwards, there is a stop
		// event generated which will call UnEnforce. However, in this case there is no guarantee that PUPolicy has
		// actually ever been set.
		zap.L().Debug("modeTypeFromPolicy received no PU policy", zap.String("name", runtime.Name()))
		return t.puTypeToEnforcerType[runtime.PUType()]
	}

	switch policyInfo.EnforcerType() {
	case policy.EnforcerMapping:
		return t.puTypeToEnforcerType[runtime.PUType()]
	case policy.EnvoyAuthorizerEnforcer:
		switch runtime.PUType() {
		case common.KubernetesPU:
			fallthrough
		case common.ContainerPU:
			return constants.RemoteContainerEnvoyAuthorizer
		case common.HostPU:
			fallthrough
		case common.HostNetworkPU:
			fallthrough
		case common.LinuxProcessPU, common.WindowsProcessPU:
			return constants.LocalEnvoyAuthorizer
		default:
			return t.puTypeToEnforcerType[runtime.PUType()]
		}
	default:
		return t.puTypeToEnforcerType[runtime.PUType()]
	}
}
