// +build linux

package remoteenforcer

/*
#cgo CFLAGS: -Wall
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/controller/constants"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer"
	_ "github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/nsenter" // nolint
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme-lib/controller/internal/supervisor"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/packetprocessor"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/remoteenforcer/internal/statsclient"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/remoteenforcer/internal/statscollector"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/secrets"
	"github.com/aporeto-inc/trireme-lib/policy"
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
) (s RemoteIntf, err error) {

	var collector statscollector.Collector
	if statsClient == nil {
		collector = statscollector.NewCollector()
		statsClient, err = statsclient.NewStatsClient(collector)
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
		ctx:            ctx,
		cancel:         cancel,
	}, nil
}

// getCEnvVariable returns an environment variable set in the c context
func getCEnvVariable(name string) string {

	val := C.getenv(C.CString(name))
	if val == nil {
		return ""
	}

	return C.GoString(val)
}

// setup an enforcer
func (s *RemoteEnforcer) setupEnforcer(req rpcwrapper.Request) (err error) {

	if s.enforcer != nil {
		return nil
	}

	payload := req.Payload.(rpcwrapper.InitRequestPayload)

	switch payload.SecretType {
	case secrets.PKIType:
		// PKI params
		s.secrets, err = secrets.NewPKISecrets(payload.PrivatePEM, payload.PublicPEM, payload.CAPEM, map[string]*ecdsa.PublicKey{})
		if err != nil {
			return fmt.Errorf("unable to initialize secrets: %s", err)
		}

	case secrets.PSKType:
		// PSK params
		s.secrets = secrets.NewPSKSecrets(payload.PrivatePEM)

	case secrets.PKICompactType:
		// Compact PKI Parameters
		s.secrets, err = secrets.NewCompactPKIWithTokenCA(payload.PrivatePEM, payload.PublicPEM, payload.CAPEM, payload.TokenKeyPEMs, payload.Token)
		if err != nil {
			return fmt.Errorf("unable to initialize secrets: %s", err)
		}

	case secrets.PKINull:
		// Null Encryption
		zap.L().Info("Using Null Secrets")
		s.secrets, err = secrets.NewNullPKI(payload.PrivatePEM, payload.PublicPEM, payload.CAPEM)
		if err != nil {
			return fmt.Errorf("unable to initialize secrets: %s", err)
		}
	}

	// New returns a new policy enforcer
	// TODO: return an err to tell why!
	if s.enforcer = enforcer.New(
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
	); s.enforcer == nil {
		return errors.New("unable to setup enforcer: we don't know as this function does not return an error")
	}

	return nil
}

// InitEnforcer is a function called from the controller using RPC. It intializes
// data structure required by the remote enforcer
func (s *RemoteEnforcer) InitEnforcer(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	// Check if successfully switched namespace
	nsEnterState := getCEnvVariable(constants.EnvNsenterErrorState)
	nsEnterLogMsg := getCEnvVariable(constants.EnvNsenterLogs)
	if nsEnterState != "" {
		zap.L().Error("Remote enforcer failed",
			zap.String("nsErr", nsEnterState),
			zap.String("nsLogs", nsEnterLogMsg),
		)
		resp.Status = fmt.Sprintf("Remote enforcer failed: %s", nsEnterState)
		return fmt.Errorf(resp.Status)
	}

	pid := strconv.Itoa(os.Getpid())
	netns, err := exec.Command("ip", "netns", "identify", pid).Output()
	if err != nil {
		zap.L().Error("Remote enforcer failed: unable to identify namespace",
			zap.String("nsErr", nsEnterState),
			zap.String("nsLogs", nsEnterLogMsg),
			zap.Error(err),
		)
		resp.Status = fmt.Sprintf("Remote enforcer failed: unable to identify namespace: %s", err)
		// Dont return error to close RPC channel
	}

	netnsString := strings.TrimSpace(string(netns))
	if netnsString == "" {
		zap.L().Error("Remote enforcer failed: not running in a namespace",
			zap.String("nsErr", nsEnterState),
			zap.String("nsLogs", nsEnterLogMsg),
		)
		resp.Status = "not running in a namespace"
		// Dont return error to close RPC channel
	}

	zap.L().Debug("Remote enforcer launched",
		zap.String("nsLogs", nsEnterLogMsg),
	)

	if !s.rpcHandle.CheckValidity(&req, s.rpcSecret) {
		resp.Status = fmt.Sprintf("init message authentication failed: %s", resp.Status)
		return fmt.Errorf(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()

	if err := s.setupEnforcer(req); err != nil {
		resp.Status = err.Error()
		return nil
	}

	if err := s.enforcer.Run(s.ctx); err != nil {
		resp.Status = err.Error()
		return nil
	}

	if err := s.statsClient.Run(s.ctx); err != nil {
		resp.Status = err.Error()
		return nil
	}

	resp.Status = ""
	return nil
}

// InitSupervisor is a function called from the controller over RPC. It initializes data structure required by the supervisor
func (s *RemoteEnforcer) InitSupervisor(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpcHandle.CheckValidity(&req, s.rpcSecret) {
		resp.Status = fmt.Sprintf("supervisor init message auth failed")
		return fmt.Errorf(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()

	payload := req.Payload.(rpcwrapper.InitSupervisorPayload)
	if s.supervisor == nil {
		switch payload.CaptureMethod {
		case rpcwrapper.IPSets:
			//TO DO
			return errors.New("ipsets not supported yet")
		default:
			supervisorHandle, err := supervisor.NewSupervisor(
				s.collector,
				s.enforcer,
				constants.RemoteContainer,
				payload.TriremeNetworks,
			)
			if err != nil {
				zap.L().Error("unable to instantiate the iptables supervisor", zap.Error(err))
				return err
			}
			s.supervisor = supervisorHandle
		}

		if err := s.supervisor.Run(s.ctx); err != nil {
			zap.L().Error("unable to start the supervisor", zap.Error(err))
		}

		if s.service != nil {
			s.service.Initialize(s.secrets, s.enforcer.GetFilterQueue())
		}

	} else {
		if err := s.supervisor.SetTargetNetworks(payload.TriremeNetworks); err != nil {
			zap.L().Error("unable to set target networks", zap.Error(err))
		}
	}

	resp.Status = ""

	return nil
}

// Supervise This method calls the supervisor method on the supervisor created during initsupervisor
func (s *RemoteEnforcer) Supervise(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpcHandle.CheckValidity(&req, s.rpcSecret) {
		resp.Status = fmt.Sprintf("supervise message auth failed")
		return fmt.Errorf(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()

	payload := req.Payload.(rpcwrapper.SuperviseRequestPayload)
	pupolicy := policy.NewPUPolicy(payload.ManagementID,
		payload.TriremeAction,
		payload.ApplicationACLs,
		payload.NetworkACLs,
		payload.TransmitterRules,
		payload.ReceiverRules,
		payload.Identity,
		payload.Annotations,
		payload.PolicyIPs,
		payload.TriremeNetworks,
		payload.ExcludedNetworks,
		payload.ProxiedServices,
		payload.ExposedServices,
		payload.DependentServices)

	runtime := policy.NewPURuntimeWithDefaults()

	puInfo := policy.PUInfoFromPolicyAndRuntime(payload.ContextID, pupolicy, runtime)

	// TODO - Set PID to 1 - needed only for statistics
	puInfo.Runtime.SetPid(1)

	zap.L().Debug("Called Supervise Start in remote_enforcer")

	err := s.supervisor.Supervise(payload.ContextID, puInfo)
	if err != nil {
		zap.L().Error("Unable to initialize supervisor",
			zap.String("ContextID", payload.ContextID),
			zap.Error(err),
		)
		resp.Status = err.Error()
		return err
	}

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

	payload := req.Payload.(rpcwrapper.UnEnforcePayload)
	return s.enforcer.Unenforce(payload.ContextID)
}

// Unsupervise This method calls the unsupervise method on the supervisor created during initsupervisor
func (s *RemoteEnforcer) Unsupervise(req rpcwrapper.Request, resp *rpcwrapper.Response) error {

	if !s.rpcHandle.CheckValidity(&req, s.rpcSecret) {
		resp.Status = "unsupervise message auth failed"
		return fmt.Errorf(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()

	payload := req.Payload.(rpcwrapper.UnSupervisePayload)
	return s.supervisor.Unsupervise(payload.ContextID)
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

	pupolicy := policy.NewPUPolicy(payload.ManagementID,
		payload.TriremeAction,
		payload.ApplicationACLs,
		payload.NetworkACLs,
		payload.TransmitterRules,
		payload.ReceiverRules,
		payload.Identity,
		payload.Annotations,
		payload.PolicyIPs,
		payload.TriremeNetworks,
		payload.ExcludedNetworks,
		payload.ProxiedServices,
		payload.ExposedServices,
		payload.DependentServices)

	runtime := policy.NewPURuntimeWithDefaults()
	puInfo := policy.PUInfoFromPolicyAndRuntime(payload.ContextID, pupolicy, runtime)
	if puInfo == nil {
		return errors.New("unable to instantiate pu info")
	}
	if s.enforcer == nil {
		resp.Status = "Cannot initialize enforcer - enforcer is nil"
		return fmt.Errorf(resp.Status)
	}

	if err := s.enforcer.Enforce(payload.ContextID, puInfo); err != nil {
		resp.Status = err.Error()
		return err
	}

	zap.L().Debug("Enforcer enabled", zap.String("contextID", payload.ContextID))

	resp.Status = ""

	return nil
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
		resp.Status = "enforce message auth failed"
		return fmt.Errorf(resp.Status)
	}

	cmdLock.Lock()
	defer cmdLock.Unlock()
	if s.enforcer != nil {
		return nil
	}

	payload := req.Payload.(rpcwrapper.UpdateSecretsPayload)

	switch payload.SecretType {
	case secrets.PKIType:
		// PKI params
		s.secrets, err = secrets.NewPKISecrets(payload.PrivatePEM, payload.PublicPEM, payload.CAPEM, map[string]*ecdsa.PublicKey{})
		if err != nil {
			return fmt.Errorf("unable to initialize secrets: %s", err)
		}

	case secrets.PSKType:
		// PSK params
		s.secrets = secrets.NewPSKSecrets(payload.PrivatePEM)

	case secrets.PKICompactType:
		// Compact PKI Parameters
		s.secrets, err = secrets.NewCompactPKIWithTokenCA(payload.PrivatePEM, payload.PublicPEM, payload.CAPEM, payload.TokenKeyPEMs, payload.Token)
		if err != nil {
			return fmt.Errorf("unable to initialize secrets: %s", err)
		}

	case secrets.PKINull:
		// Null Encryption
		zap.L().Info("Using Null Secrets")
		s.secrets, err = secrets.NewNullPKI(payload.PrivatePEM, payload.PublicPEM, payload.CAPEM)
		if err != nil {
			return fmt.Errorf("unable to initialize secrets: %s", err)
		}
	}

	return nil

}

// LaunchRemoteEnforcer launches a remote enforcer
func LaunchRemoteEnforcer(service packetprocessor.PacketProcessor) error {

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
	server, err := newServer(ctx, cancelMainCtx, service, rpcHandle, namedPipe, secret, nil)
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
