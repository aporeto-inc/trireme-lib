//Package enforcerLauncher :: This is the implementation of the RPC client
//It implementes the interface PolicyEnforcer and forwards these requests to the actual enforcer
package enforcerLauncher

import (
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcWrapper"
	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/remote/launch"
)

//ErrFailedtoLaunch exported
var ErrFailedtoLaunch = errors.New("Failed to Launch")

//ErrExpectedEnforcer exported
var ErrExpectedEnforcer = errors.New("Process was not launched")

// ErrEnforceFailed exported
var ErrEnforceFailed = errors.New("Failed to enforce rules")

// ErrInitFailed exported
var ErrInitFailed = errors.New("Failed remote Init")

type enforcerInitValue struct {
	process    *os.Process
	client     *rpcWrapper.RPCHdl
	socketPath string
}
type launcherState struct {
	MutualAuth bool
	Secrets    tokens.Secrets
	serverID   string
	validity   time.Duration
}

func (s *launcherState) InitRemoteEnforcer(contextID string, puInfo *policy.PUInfo) error {
	payload := new(rpcWrapper.InitRequestPayload)
	request := new(rpcWrapper.Request)
	resp := new(rpcWrapper.Response)

	payload.MutualAuth = s.MutualAuth
	payload.Validity = s.validity
	pem := s.Secrets.(keyPEM)
	payload.SecretType = s.Secrets.Type()

	payload.PublicPEM = pem.TransmittedPEM()
	payload.PrivatePEM = pem.EncodingPEM()
	payload.CAPEM = pem.AuthPEM()

	payload.ContextID = contextID

	request.Payload = payload
	gob.Register(rpcWrapper.InitRequestPayload{})
	err := rpcWrapper.RemoteCall(contextID, "Server.InitEnforcer", request, resp)
	if err != nil {
		fmt.Println(err)
	}
	if resp.Status != nil {
		fmt.Println(resp.Status)
		panic("Init Failed")
	}

	return nil

}
func (s *launcherState) Enforce(contextID string, puInfo *policy.PUInfo) error {
	err := ProcessMon.LaunchProcess(contextID, puInfo.Runtime.Pid())
	if err != nil {
		return err
	}

	s.InitRemoteEnforcer(contextID, puInfo)
	request := new(rpcWrapper.Request)

	enfResp := new(rpcWrapper.Response)
	enfReq := new(rpcWrapper.EnforcePayload)
	enfReq.ContextID = contextID
	enfReq.PuPolicy = puInfo.Policy
	request.Payload = enfReq
	gob.Register(rpcWrapper.EnforcePayload{})
	err = rpcWrapper.RemoteCall(contextID, "Server.Enforce", request, enfResp)
	//err = rpcClient.Client.Call("Server.Enforce", request, enfResp)
	if err != nil {
		log.WithFields(log.Fields{
			"package": "enforcerLauncher",
			"error":   err}).Fatal("Failed to Enforce remote enforcer")
		return ErrEnforceFailed
	}
	return nil
}

// Unenforce stops enforcing policy for the given IP.
func (s *launcherState) Unenforce(contextID string) error {
	rpcClient, _ := rpcWrapper.GetRPCClient(contextID)
	unenfreq := new(rpcWrapper.UnEnforcePayload)
	unenfresp := new(rpcWrapper.UnEnforceResponsePayload)
	unenfreq.ContextID = contextID
	rpcClient.Client.Call("Server.Unenforce", unenfreq, unenfresp)
	if ProcessMon.GetExitStatus(contextID) == false {
		ProcessMon.SetExitStatus(contextID, true)
	} else {
		ProcessMon.KillProcess(contextID)
	}
	return nil
}

// GetFilterQueue returns the current FilterQueueConfig.
func (s *launcherState) GetFilterQueue() *enforcer.FilterQueue {
	fqConfig := &enforcer.FilterQueue{
		NetworkQueue:              enforcer.DefaultNetworkQueue,
		NetworkQueueSize:          enforcer.DefaultQueueSize,
		NumberOfNetworkQueues:     enforcer.DefaultNumberOfQueues,
		ApplicationQueue:          enforcer.DefaultApplicationQueue,
		ApplicationQueueSize:      enforcer.DefaultQueueSize,
		NumberOfApplicationQueues: enforcer.DefaultNumberOfQueues,
	}
	return fqConfig
}

// Start starts the PolicyEnforcer.
//This method on the client does not do anything.
//At this point no container has started so we don't know
//what namespace to launch the new container
func (s *launcherState) Start() error {
	fmt.Println("Called Start")
	return nil
}

// Stop stops the PolicyEnforcer.
func (s *launcherState) Stop() error {
	return nil
}

//NewDatapathEnforcer exported
func NewDatapathEnforcer(mutualAuth bool,
	filterQueue *enforcer.FilterQueue,
	collector collector.EventCollector,
	service enforcer.PacketProcessor,
	secrets tokens.Secrets,
	serverID string,
	validity time.Duration,
) enforcer.PolicyEnforcer {
	launcher := &launcherState{
		MutualAuth: mutualAuth,
		Secrets:    secrets,
		serverID:   serverID,
		validity:   validity,
	}
	return launcher
}

//NewDefaultDatapathEnforcer exported
func NewDefaultDatapathEnforcer(serverID string,
	collector collector.EventCollector,
	secrets tokens.Secrets,
) enforcer.PolicyEnforcer {
	mutualAuthorization := false
	fqConfig := &enforcer.FilterQueue{
		NetworkQueue:              enforcer.DefaultNetworkQueue,
		NetworkQueueSize:          enforcer.DefaultQueueSize,
		NumberOfNetworkQueues:     enforcer.DefaultNumberOfQueues,
		ApplicationQueue:          enforcer.DefaultApplicationQueue,
		ApplicationQueueSize:      enforcer.DefaultQueueSize,
		NumberOfApplicationQueues: enforcer.DefaultNumberOfQueues,
	}

	validity := time.Hour * 8760
	return NewDatapathEnforcer(
		mutualAuthorization,
		fqConfig,
		collector,
		nil,
		secrets,
		serverID,
		validity,
	)
}
