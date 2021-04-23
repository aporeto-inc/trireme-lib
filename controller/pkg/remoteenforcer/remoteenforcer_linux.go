// +build linux

package remoteenforcer

/*
#cgo CFLAGS: -Wall
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/blang/semver"
	"go.aporeto.io/enforcerd/internal/diagnostics"
	"go.aporeto.io/enforcerd/internal/logging/remotelog"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer"
	_ "go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/nsenter" // nolint
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/supervisor"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/remoteenforcer/internal/client"
	reports "go.aporeto.io/enforcerd/trireme-lib/controller/pkg/remoteenforcer/internal/client/reportsclient"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/remoteenforcer/internal/client/statsclient"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/remoteenforcer/internal/statscollector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/remoteenforcer/internal/tokenissuer"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets/rpc"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// Initialization functions as variables in order to enable testing.
var (
	createEnforcer = enforcer.New

	createSupervisor = supervisor.NewSupervisor
)

var cmdLock sync.Mutex

// newRemoteEnforcer starts a new server
func newRemoteEnforcer(
	ctx context.Context,
	rpcHandle rpcwrapper.RPCServer,
	secret string,
	statsClient client.Reporter,
	collector statscollector.Collector,
	reportsClient client.Reporter,
	tokenIssuer tokenissuer.TokenClient,
	logLevel string,
	logFormat string,
	logID string,
	numQueues int,
	enforcerType policy.EnforcerType,
	agentVersion semver.Version,
) (*RemoteEnforcer, error) {

	var err error

	if collector == nil {
		collector = statscollector.NewCollector()
	}

	if statsClient == nil {
		statsClient, err = statsclient.NewStatsClient(collector)
		if err != nil {
			return nil, err
		}
	}

	if reportsClient == nil {
		reportsClient, err = reports.NewClient(collector)
		if err != nil {
			return nil, err
		}
	}

	if tokenIssuer == nil {
		tokenIssuer, err = tokenissuer.NewClient()
		if err != nil {
			return nil, err
		}

	}

	procMountPoint := os.Getenv(constants.EnvMountPoint)
	if procMountPoint == "" {
		procMountPoint = constants.DefaultProcMountPoint
	}

	fqConfig := fqconfig.NewFilterQueue(
		numQueues,
		[]string{"0.0.0.0/0"},
	)

	return &RemoteEnforcer{
		collector:      collector,
		rpcSecret:      secret,
		rpcHandle:      rpcHandle,
		procMountPoint: procMountPoint,
		statsClient:    statsClient,
		reportsClient:  reportsClient,
		ctx:            ctx,
		exit:           make(chan bool),
		tokenIssuer:    tokenIssuer,
		enforcerType:   enforcerType,
		agentVersion:   agentVersion,
		config:         logConfig{logLevel: logLevel, logFormat: logFormat, logID: logID},
		fqConfig:       fqConfig,
	}, nil
}

// InitEnforcer is a function called from the controller using RPC. It intializes
// data structure required by the remote enforcer
func (s *RemoteEnforcer) InitEnforcer(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	zap.L().Debug("Configuring remote enforcer")

	if !s.rpcHandle.CheckValidity(&req, s.rpcSecret) {
		resp.Status = fmt.Sprintf("init message authentication failed") // nolint:gosimple
		return fmt.Errorf(resp.Status)
	}
	cmdLock.Lock()
	defer cmdLock.Unlock()

	payload, ok := req.Payload.(rpcwrapper.InitRequestPayload)
	if !ok {
		resp.Status = fmt.Sprintf("invalid request payload") // nolint:gosimple
		return fmt.Errorf(resp.Status)
	}

	if s.supervisor != nil || s.enforcer != nil {
		resp.Status = fmt.Sprintf("remote enforcer is already initialized") // nolint:gosimple
		return fmt.Errorf(resp.Status)
	}

	var err error

	defer func() {
		if err != nil {
			s.cleanup()
		}
	}()

	if err = s.setupEnforcer(&payload); err != nil {
		resp.Status = err.Error()
		return fmt.Errorf(resp.Status)
	}

	if err = s.setupSupervisor(&payload); err != nil {
		resp.Status = err.Error()
		return fmt.Errorf(resp.Status)
	}

	if err = s.enforcer.Run(s.ctx); err != nil {
		resp.Status = err.Error()
		return fmt.Errorf(resp.Status)
	}

	if err = s.statsClient.Run(s.ctx); err != nil {
		resp.Status = err.Error()
		return fmt.Errorf(resp.Status)
	}

	if err = s.supervisor.Run(s.ctx); err != nil {
		resp.Status = err.Error()
		return fmt.Errorf(resp.Status)
	}

	if err = s.reportsClient.Run(s.ctx); err != nil {
		resp.Status = "ReportsClient" + err.Error()
		return fmt.Errorf(resp.Status)
	}

	if err = s.tokenIssuer.Run(s.ctx); err != nil {
		resp.Status = "TokenIssuer" + err.Error()
		return fmt.Errorf(resp.Status)
	}

	resp.Status = ""

	return nil
}

// Enforce this method calls the enforce method on the enforcer created during initenforcer
func (s *RemoteEnforcer) Enforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpcHandle.CheckValidity(&req, s.rpcSecret) {
		resp.Status = "enforce message auth failed"
		return fmt.Errorf(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()

	payload, ok := req.Payload.(rpcwrapper.EnforcePayload)
	if !ok {
		resp.Status = "invalid enforcer payload"
		return fmt.Errorf(resp.Status)
	}

	plc, err := payload.Policy.ToPrivatePolicy(s.ctx, true)
	if err != nil {
		return err
	}

	runtime := policy.NewPURuntimeWithDefaults()

	puInfo := &policy.PUInfo{
		ContextID: payload.ContextID,
		Policy:    plc,
		Runtime:   runtime,
	}

	if s.enforcer == nil || s.supervisor == nil {
		resp.Status = "enforcer not initialized - cannot enforce"
		return fmt.Errorf(resp.Status)
	}

	// If any error happens, cleanup everything on exit so that we can recover
	// by launcing a new remote.
	defer func() {
		if err != nil {
			s.cleanup()
		}
	}()

	if err = s.supervisor.Supervise(payload.ContextID, puInfo); err != nil {
		resp.Status = err.Error()
		return err
	}

	if err = s.enforcer.Enforce(s.ctx, payload.ContextID, puInfo); err != nil {
		resp.Status = err.Error()
		return err
	}

	resp.Status = ""

	return nil
}

// Unenforce this method calls the unenforce method on the enforcer created from initenforcer
func (s *RemoteEnforcer) Unenforce(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpcHandle.CheckValidity(&req, s.rpcSecret) {
		resp.Status = "unenforce message auth failed"
		return fmt.Errorf(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()

	s.statsClient.Send() // nolint: errcheck

	payload, ok := req.Payload.(rpcwrapper.UnEnforcePayload)
	if !ok {
		resp.Status = "invalid unenforcer payload"
		return fmt.Errorf(resp.Status)
	}

	var err error

	// If any error happens, cleanup everything on exit so that we can recover
	// by launcing a new remote.
	defer func() {
		if err != nil {
			s.cleanup()
		}
	}()

	if err = s.supervisor.Unsupervise(payload.ContextID); err != nil {
		resp.Status = err.Error()
		return fmt.Errorf("unable to clean supervisor: %s", err)
	}

	if err = s.enforcer.Unenforce(s.ctx, payload.ContextID); err != nil {
		resp.Status = err.Error()
		return fmt.Errorf("unable to stop enforcer: %s", err)
	}

	return nil
}

// SetTargetNetworks calls the same method on the actual enforcer
func (s *RemoteEnforcer) SetTargetNetworks(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	var err error
	if !s.rpcHandle.CheckValidity(&req, s.rpcSecret) {
		resp.Status = "SetTargetNetworks message auth failed" // nolint
		return fmt.Errorf(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()

	if s.enforcer == nil || s.supervisor == nil {
		return fmt.Errorf(resp.Status)
	}

	payload := req.Payload.(rpcwrapper.SetTargetNetworksPayload)

	// If any error happens, cleanup everything on exit so that we can recover
	// by launcing a new remote.
	defer func() {
		if err != nil {
			s.cleanup()
		}
	}()

	if err = s.enforcer.SetTargetNetworks(payload.Configuration); err != nil {
		return err
	}

	err = s.supervisor.SetTargetNetworks(payload.Configuration)

	return err
}

// EnforcerExit is processing messages from the remote that are requesting an exit. In this
// case we simply cancel the context.
func (s *RemoteEnforcer) EnforcerExit(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	s.cleanup()

	s.exit <- true

	return nil
}

// UpdateSecrets updates the secrets used by the remote enforcer
func (s *RemoteEnforcer) UpdateSecrets(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	var err error
	if !s.rpcHandle.CheckValidity(&req, s.rpcSecret) {
		resp.Status = "updatesecrets auth failed"
		return fmt.Errorf(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()
	if s.enforcer == nil {
		return fmt.Errorf(resp.Status)
	}

	// If any error happens, cleanup everything on exit so that we can recover
	// by launcing a new remote.
	defer func() {
		if err != nil {
			s.cleanup()
		}
	}()

	payload := req.Payload.(rpcwrapper.UpdateSecretsPayload)
	s.secrets, err = rpc.NewSecrets(payload.Secrets)
	if err != nil {
		return err
	}

	err = s.enforcer.UpdateSecrets(s.secrets)

	return err
}

// EnableDatapathPacketTracing enable nfq datapath packet tracing
func (s *RemoteEnforcer) EnableDatapathPacketTracing(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpcHandle.CheckValidity(&req, s.rpcSecret) {
		resp.Status = "enable datapath packet tracing auth failed"
		return fmt.Errorf(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()

	payload := req.Payload.(rpcwrapper.EnableDatapathPacketTracingPayLoad)

	if err := s.enforcer.EnableDatapathPacketTracing(s.ctx, payload.ContextID, payload.Direction, payload.Interval); err != nil {
		resp.Status = err.Error()
		return err
	}

	resp.Status = ""
	return nil
}

// EnableIPTablesPacketTracing enables iptables trace packet tracing
func (s *RemoteEnforcer) EnableIPTablesPacketTracing(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpcHandle.CheckValidity(&req, s.rpcSecret) {
		resp.Status = "enable iptable packet tracing auth failed"
		return fmt.Errorf(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()

	payload := req.Payload.(rpcwrapper.EnableIPTablesPacketTracingPayLoad)

	if err := s.supervisor.EnableIPTablesPacketTracing(s.ctx, payload.ContextID, payload.Interval); err != nil {
		resp.Status = err.Error()
		return err
	}

	resp.Status = ""
	return nil
}

// Ping runs ping to the given config
func (s *RemoteEnforcer) Ping(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpcHandle.CheckValidity(&req, s.rpcSecret) {
		resp.Status = "ping auth failed"
		return fmt.Errorf(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()

	payload := req.Payload.(rpcwrapper.PingPayload)

	if err := s.enforcer.Ping(s.ctx, payload.ContextID, payload.PingConfig); err != nil {
		resp.Status = err.Error()
		return err
	}

	resp.Status = ""
	return nil
}

// DebugCollect collects the desired debug information
func (s *RemoteEnforcer) DebugCollect(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpcHandle.CheckValidity(&req, s.rpcSecret) {
		resp.Status = "debug collect auth failed"
		return fmt.Errorf(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()

	payload := req.Payload.(rpcwrapper.DebugCollectPayload)

	var commandOutput string
	var pid int

	if payload.CommandExec != "" {
		if values := strings.Split(payload.CommandExec, " "); len(values) >= 1 {
			cmd := exec.CommandContext(s.ctx, values[0], values[1:]...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				resp.Status = err.Error()
				return err
			}
			commandOutput = string(output)
		}
	} else if payload.PcapFilePath != "" {
		cmd, err := diagnostics.StartTcpdump(s.ctx, payload.PcapFilePath, payload.PcapFilter)
		if err != nil {
			resp.Status = err.Error()
			return err
		}

		// spawn goroutine to call Wait() so we don't have defunct child process
		go func() {
			if err := cmd.Wait(); err != nil {
				zap.L().Warn("DebugCollect Wait failed on tcpdump process", zap.Error(err))
			}
		}()

		pid = cmd.Process.Pid
	} else {
		// otherwise, return pid of remote enforcer
		pid = os.Getpid()
	}

	resp.Status = ""
	resp.Payload = rpcwrapper.DebugCollectResponsePayload{
		ContextID:     payload.ContextID,
		PID:           pid,
		CommandOutput: commandOutput,
	}
	return nil
}

// SetLogLevel sets log level.
func (s *RemoteEnforcer) SetLogLevel(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpcHandle.CheckValidity(&req, s.rpcSecret) {
		resp.Status = "set log level auth failed"
		return fmt.Errorf(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()
	if s.enforcer == nil {
		return fmt.Errorf(resp.Status)
	}

	payload := req.Payload.(rpcwrapper.SetLogLevelPayload)

	newLevel := triremeLogLevelToString(payload.Level)
	if payload.Level != "" && s.config.logLevel != newLevel {
		remotelog.SetupRemoteLogger(newLevel, s.config.logFormat, s.config.logID) // nolint: errcheck
		s.config.logLevel = newLevel

		if err := s.enforcer.SetLogLevel(payload.Level); err != nil {
			resp.Status = err.Error()
			return err
		}
	}

	resp.Status = ""
	return nil
}

func triremeLogLevelToString(level constants.LogLevel) string {
	switch level {
	case constants.Debug:
		return "debug"
	case constants.Trace:
		return "trace"
	case constants.Error:
		return "error"
	case constants.Info:
		return "info"
	case constants.Warn:
		return "warn"
	default:
		return "info"
	}
}

// setup an enforcer
func (s *RemoteEnforcer) setupEnforcer(payload *rpcwrapper.InitRequestPayload) error {

	var err error

	s.secrets, err = rpc.NewSecrets(payload.Secrets)
	if err != nil {
		return err
	}

	// we are usually always starting RemoteContainer enforcers,
	// however, if envoy is requested, we change the mode to RemoteContainerEnvoyAuthorizer
	mode := constants.RemoteContainer
	if s.enforcerType == policy.EnvoyAuthorizerEnforcer {
		mode = constants.RemoteContainerEnvoyAuthorizer
	}

	if s.enforcer, err = createEnforcer(
		payload.MutualAuth,
		s.fqConfig,
		s.collector,
		s.secrets,
		payload.ServerID,
		payload.Validity,
		mode,
		s.procMountPoint,
		payload.ExternalIPCacheTimeout,
		payload.PacketLogs,
		payload.Configuration,
		s.tokenIssuer,
		payload.IsBPFEnabled,
		s.agentVersion,
		payload.ServiceMeshType,
	); err != nil || s.enforcer == nil {
		return fmt.Errorf("Error while initializing remote enforcer, %s", err)
	}

	return nil
}

func (s *RemoteEnforcer) setupSupervisor(payload *rpcwrapper.InitRequestPayload) error {

	// we are usually always starting RemoteContainer enforcers,
	// however, if envoy is requested, we change the mode to RemoteContainerEnvoyAuthorizer
	mode := constants.RemoteContainer
	if s.enforcerType == policy.EnvoyAuthorizerEnforcer {
		mode = constants.RemoteContainerEnvoyAuthorizer
	}

	h, err := createSupervisor(
		s.collector,
		s.enforcer,
		mode,
		payload.Configuration,
		payload.IPv6Enabled,
		payload.IPTablesLockfile,
	)
	if err != nil {
		return fmt.Errorf("unable to setup supervisor: %s", err)
	}
	s.supervisor = h

	return nil
}

// cleanup cleans all the acls and any state of the local enforcer.
func (s *RemoteEnforcer) cleanup() {

	if s.supervisor != nil {
		if err := s.supervisor.CleanUp(); err != nil {
			zap.L().Error("unable to clean supervisor state", zap.Error(err))
		}
	}

	if s.enforcer != nil {
		if err := s.enforcer.CleanUp(); err != nil {
			zap.L().Error("unable to clean enforcer state", zap.Error(err))
		}
	}

	if s.service != nil {
		if err := s.service.Stop(); err != nil {
			zap.L().Error("unable to clean service state", zap.Error(err))
		}
	}
}

// LaunchRemoteEnforcer launches a remote enforcer
func LaunchRemoteEnforcer(ctx context.Context, logLevel, logFormat, logID string, numQueues int, agentVersion semver.Version) error {

	// Before doing anything validate that we are in the right namespace.
	if err := validateNamespace(); err != nil {
		return err
	}

	namedPipe := os.Getenv(constants.EnvContextSocket)
	secret := os.Getenv(constants.EnvRPCClientSecret)
	if secret == "" {
		zap.L().Fatal("No secret found")
	}
	os.Setenv(constants.EnvRPCClientSecret, "") // nolint: errcheck

	flag := unix.SIGHUP
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(flag), 0, 0, 0); err != nil {
		return err
	}

	enforcerType, err := policy.EnforcerTypeFromString(os.Getenv(constants.EnvEnforcerType))
	if err != nil {
		return err
	}

	rpcHandle := rpcwrapper.NewRPCServer()
	re, err := newRemoteEnforcer(ctx, rpcHandle, secret, nil, nil, nil, nil, logLevel, logFormat, logID, numQueues, enforcerType, agentVersion)
	if err != nil {
		return err
	}

	go func() {
		if err := rpcHandle.StartServer(ctx, "unix", namedPipe, re); err != nil {
			zap.L().Fatal("Failed to start the RPC server", zap.Error(err))
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)

	select {

	case <-re.exit:
		zap.L().Info("Remote enforcer exiting ...")

	case sig := <-c:
		zap.L().Warn("Remote enforcer received a signal. exiting ...", zap.Any("signal", sig))
		re.cleanup()
		// TODO would be useful to set and return an exit code (instead of nil) to indicate the signal received

	case <-ctx.Done():
		re.cleanup()
	}

	return nil
}

// getCEnvVariable returns an environment variable set in the c context
func getCEnvVariable(name string) string {

	val := C.getenv(C.CString(name))
	if val == nil {
		return ""
	}

	return C.GoString(val)
}

func validateNamespace() error {
	// Check if successfully switched namespace
	nsEnterState := getCEnvVariable(constants.EnvNsenterErrorState)
	nsEnterLogMsg := getCEnvVariable(constants.EnvNsenterLogs)
	if nsEnterState != "" {
		return fmt.Errorf("nsErr: %s nsLogs: %s", nsEnterState, nsEnterLogMsg)
	}

	return nil
}
