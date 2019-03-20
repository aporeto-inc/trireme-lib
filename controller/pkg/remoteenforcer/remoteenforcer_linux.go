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
	"strconv"
	"strings"
	"sync"
	"syscall"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer"
	_ "go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/nsenter" // nolint
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/internal/supervisor"
	"go.aporeto.io/trireme-lib/controller/pkg/packetprocessor"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/debugclient"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/statsclient"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/statscollector"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

var cmdLock sync.Mutex

// newServer starts a new server
func newServer(
	ctx context.Context,
	cancel context.CancelFunc,
	service packetprocessor.PacketProcessor,
	rpcHandle rpcwrapper.RPCServer,
	rpcChannel string,
	secret string,
	statsClient statsclient.StatsClient,
	debugClient debugclient.DebugClient,
) (s RemoteIntf, err error) {

	var collector statscollector.Collector
	if statsClient == nil {
		collector = statscollector.NewCollector()
		statsClient, err = statsclient.NewStatsClient(collector)
		if err != nil {
			return nil, err
		}
	}
	if debugClient == nil {
		debugClient, err = debugclient.NewDebugClient(collector)
		if err != nil {
			return nil, err
		}
	}
	procMountPoint := os.Getenv(constants.EnvMountPoint)
	if procMountPoint == "" {
		procMountPoint = constants.DefaultProcMountPoint
	}

	return &RemoteEnforcer{
		collector:      collector,
		service:        service,
		rpcChannel:     rpcChannel,
		rpcSecret:      secret,
		rpcHandle:      rpcHandle,
		procMountPoint: procMountPoint,
		statsClient:    statsClient,
		debugClient:    debugClient,
		ctx:            ctx,
		cancel:         cancel,
	}, nil
}

// InitEnforcer is a function called from the controller using RPC. It intializes
// data structure required by the remote enforcer
func (s *RemoteEnforcer) InitEnforcer(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	zap.L().Debug("Configuring remote enforcer")

	if !s.rpcHandle.CheckValidity(&req, s.rpcSecret) {
		resp.Status = fmt.Sprintf("init message authentication failed: %s", resp.Status)
		return fmt.Errorf(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()

	if s.supervisor != nil || s.enforcer != nil {
		resp.Status = fmt.Sprintf("remote enforcer is already initialized")
	}

	if err := s.setupEnforcer(req); err != nil {
		resp.Status = err.Error()
		return fmt.Errorf(resp.Status)
	}

	if err := s.setupSupervisor(); err != nil {
		resp.Status = err.Error()
		return fmt.Errorf(resp.Status)
	}

	if err := s.enforcer.Run(s.ctx); err != nil {
		resp.Status = err.Error()
		return fmt.Errorf(resp.Status)
	}

	if err := s.statsClient.Run(s.ctx); err != nil {
		resp.Status = err.Error()
		return fmt.Errorf(resp.Status)
	}

	if err := s.supervisor.Run(s.ctx); err != nil {
		resp.Status = err.Error()
		return fmt.Errorf(resp.Status)
	}

	if err := s.debugClient.Run(s.ctx); err != nil {
		resp.Status = "DebugClient" + err.Error()
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

	payload := req.Payload.(rpcwrapper.EnforcePayload)

	plc, err := payload.Policy.ToPrivatePolicy(true)
	if err != nil {
		return err
	}

	puInfo := &policy.PUInfo{
		ContextID: payload.ContextID,
		Policy:    plc,
		Runtime:   policy.NewPURuntimeWithDefaults(),
	}

	if s.enforcer == nil || s.supervisor == nil {
		resp.Status = "enforcer not initialized - cannot enforce"
		return fmt.Errorf(resp.Status)
	}

	if err = s.supervisor.Supervise(payload.ContextID, puInfo); err != nil {
		resp.Status = err.Error()
		return err
	}

	if err := s.enforcer.Enforce(payload.ContextID, puInfo); err != nil {
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

	s.statsClient.SendStats()

	payload := req.Payload.(rpcwrapper.UnEnforcePayload)

	if err := s.supervisor.Unsupervise(payload.ContextID); err != nil {
		resp.Status = err.Error()
		return fmt.Errorf("unable to clean supervisor: %s", err)
	}

	if err := s.enforcer.Unenforce(payload.ContextID); err != nil {
		resp.Status = err.Error()
		return fmt.Errorf("unable to stop enforcer: %s", err)
	}

	return nil
}

// SetTargetNetworks calls the same method on the actual enforcer
func (s *RemoteEnforcer) SetTargetNetworks(req rpcwrapper.Request, resp *rpcwrapper.Response) error {
	var err error
	if !s.rpcHandle.CheckValidity(&req, s.rpcSecret) {
		resp.Status = "SetTargetNetworks message auth failed" //nolint
		return fmt.Errorf(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()
	if s.enforcer == nil {
		return fmt.Errorf(resp.Status)
	}

	payload := req.Payload.(rpcwrapper.SetTargetNetworksPayload)
	if err = s.enforcer.SetTargetNetworks(payload.Configuration); err != nil {
		return err
	}

	return s.supervisor.SetTargetNetworks(payload.Configuration)
}

// EnforcerExit is processing messages from the remote that are requesting an exit. In this
// case we simply cancel the context.
func (s *RemoteEnforcer) EnforcerExit(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if s.supervisor != nil {
		s.supervisor.CleanUp() // nolint
	}
	s.cancel()

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

	payload := req.Payload.(rpcwrapper.UpdateSecretsPayload)
	s.secrets, err = secrets.NewSecrets(payload.Secrets)
	if err != nil {
		return err
	}

	err = s.enforcer.UpdateSecrets(s.secrets)
	if err != nil {
		return err
	}
	return nil
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
	if err := s.enforcer.EnableDatapathPacketTracing(payload.ContextID, payload.Direction, payload.Interval); err != nil {
		resp.Status = err.Error()
		return err
	}
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
	if err := s.supervisor.EnableIPTablesPacketTracing(context.Background(), payload.ContextID, payload.Interval); err != nil {
		resp.Status = err.Error()
		return err
	}
	resp.Status = ""
	return nil
}

// setup an enforcer
func (s *RemoteEnforcer) setupEnforcer(req rpcwrapper.Request) error {
	var err error

	payload := req.Payload.(rpcwrapper.InitRequestPayload)

	s.secrets, err = secrets.NewSecrets(payload.Secrets)
	if err != nil {
		return err
	}

	if s.enforcer, err = enforcer.New(
		payload.MutualAuth,
		payload.FqConfig,
		s.collector,
		s.service,
		s.secrets,
		payload.ServerID,
		payload.Validity,
		constants.RemoteContainer,
		s.procMountPoint,
		payload.ExternalIPCacheTimeout,
		payload.PacketLogs,
		payload.Configuration,
	); err != nil || s.enforcer == nil {
		return fmt.Errorf("Error while initializing remote enforcer, %s", err)
	}

	return nil
}

func (s *RemoteEnforcer) setupSupervisor() error {

	h, err := supervisor.NewSupervisor(
		s.collector,
		s.enforcer,
		constants.RemoteContainer,
		nil,
		s.service,
	)
	if err != nil {
		return fmt.Errorf("unable to setup supervisor: %s", err)
	}
	s.supervisor = h

	return nil
}

// LaunchRemoteEnforcer launches a remote enforcer
func LaunchRemoteEnforcer(service packetprocessor.PacketProcessor) error {

	// Before doing anything validate that we are in the right namespace.
	if err := validateNamespace(); err != nil {
		return err
	}

	ctx, cancelMainCtx := context.WithCancel(context.Background())
	defer cancelMainCtx()

	namedPipe := os.Getenv(constants.EnvContextSocket)
	secret := os.Getenv(constants.EnvRPCClientSecret)
	if secret == "" {
		zap.L().Fatal("No secret found")
	}

	flag := unix.SIGHUP
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(flag), 0, 0, 0); err != nil {
		return err
	}

	rpcHandle := rpcwrapper.NewRPCServer()
	server, err := newServer(ctx, cancelMainCtx, service, rpcHandle, namedPipe, secret, nil, nil)
	if err != nil {
		return err
	}

	go func() {
		if err := rpcHandle.StartServer(ctx, "unix", namedPipe, server); err != nil {
			zap.L().Fatal("Failed to start the server", zap.Error(err))
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	<-c

	if err := server.EnforcerExit(rpcwrapper.Request{}, &rpcwrapper.Response{}); err != nil {
		zap.L().Fatal("Failed to stop the server", zap.Error(err))
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
		return fmt.Errorf("nsErr: %s nsLogs:", nsEnterState, nsEnterLogMsg)
	}

	pid := strconv.Itoa(os.Getpid())
	netns, err := exec.Command("ip", "netns", "identify", pid).Output()
	if err != nil {
		return fmt.Errorf("unable to identity namespace: %s", err)
	}

	netnsString := strings.TrimSpace(string(netns))
	if netnsString == "" {
		return fmt.Errorf("empty namespace - cannot launch remote enforcer")
	}

	return nil
}
