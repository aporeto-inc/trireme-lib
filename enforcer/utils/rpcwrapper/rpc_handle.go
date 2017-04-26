package rpcwrapper

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/gob"
	"fmt"

	"go.uber.org/zap"

	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"net/rpc"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/cnf/structhash"
)

// RPCHdl is a per client handle
type RPCHdl struct {
	Client  *rpc.Client
	Channel string
	Secret  string
}

// RPCWrapper  is a struct which holds stats for all rpc sesions
type RPCWrapper struct {
	rpcClientMap *cache.Cache
	contextList  []string
}

// NewRPCWrapper creates a new rpcwrapper
func NewRPCWrapper() *RPCWrapper {

	return &RPCWrapper{
		rpcClientMap: cache.NewCache(),
		contextList:  []string{},
	}
}

const (
	maxRetries     = 1000
	envRetryString = "REMOTE_RPCRETRIES"
)

// NewRPCClient exported
func (r *RPCWrapper) NewRPCClient(contextID string, channel string, sharedsecret string) error {

	RegisterTypes()

	max := maxRetries
	retries := os.Getenv(envRetryString)
	if len(retries) > 0 {
		max, _ = strconv.Atoi(retries)
	}

	numRetries := 0
	client, err := rpc.DialHTTP("unix", channel)
	for err != nil {
		numRetries++
		if numRetries >= max {
			return err
		}

		time.Sleep(5 * time.Millisecond)
		client, err = rpc.DialHTTP("unix", channel)
	}

	r.contextList = append(r.contextList, contextID)
	return r.rpcClientMap.Add(contextID, &RPCHdl{Client: client, Channel: channel, Secret: sharedsecret})

}

// GetRPCClient gets a handle to the rpc client for the contextID( enforcer in the container)
func (r *RPCWrapper) GetRPCClient(contextID string) (*RPCHdl, error) {

	val, err := r.rpcClientMap.Get(contextID)
	if err != nil {
		return nil, err
	}

	return val.(*RPCHdl), nil
}

// RemoteCall is a wrapper around rpc.Call and also ensure message integrity by adding a hmac
func (r *RPCWrapper) RemoteCall(contextID string, methodName string, req *Request, resp *Response) error {

	rpcClient, err := r.GetRPCClient(contextID)
	if err != nil {
		return err
	}

	digest := hmac.New(sha256.New, []byte(rpcClient.Secret))
	if _, err := digest.Write(structhash.Dump(req.Payload, 1)); err != nil {
		return err
	}

	req.HashAuth = digest.Sum(nil)

	return rpcClient.Client.Call(methodName, req, resp)
}

// CheckValidity checks if the received message is valid
func (r *RPCWrapper) CheckValidity(req *Request, secret string) bool {

	digest := hmac.New(sha256.New, []byte(secret))

	if _, err := digest.Write(structhash.Dump(req.Payload, 1)); err != nil {
		return false
	}

	return hmac.Equal(req.HashAuth, digest.Sum(nil))
}

//NewRPCServer returns an interface RPCServer
func NewRPCServer() RPCServer {

	return &RPCWrapper{}
}

//StartServer Starts a server and waits for new connections this function never returns
func (r *RPCWrapper) StartServer(protocol string, path string, handler interface{}) error {

	if len(path) == 0 {
		zap.L().Fatal("Sock param not passed in environment")
	}

	// Register RPC Type
	RegisterTypes()

	// Register handlers
	if err := rpc.Register(handler); err != nil {
		return err
	}
	rpc.HandleHTTP()

	// removing old path in case it exists already - error if we can't remove it
	if _, err := os.Stat(path); err == nil {

		zap.L().Warn("Socket path already exists: removing", zap.String("path", path))

		if rerr := os.Remove(path); rerr != nil {
			return fmt.Errorf("Failed to delete existing socket path %s: %s", path, rerr.Error())
		}
	}

	// Get listener
	listen, err := net.Listen(protocol, path)
	if err != nil {
		return err
	}

	go http.Serve(listen, nil) // nolint

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	if merr := listen.Close(); merr != nil {
		zap.L().Warn("Connection already closed", zap.Error(merr))
	}

	_, err = os.Stat(path)
	if !os.IsNotExist(err) {
		if err := os.Remove(path); err != nil {
			zap.L().Warn("failed to remove old path", zap.Error(err))
		}
	}

	return nil
}

// DestroyRPCClient calls close on the rpc and cleans up the connection
func (r *RPCWrapper) DestroyRPCClient(contextID string) {

	rpcHdl, _ := r.rpcClientMap.Get(contextID)
	if err := rpcHdl.(*RPCHdl).Client.Close(); err != nil {
		zap.L().Warn("Failed to close channel",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	if err := os.Remove(rpcHdl.(*RPCHdl).Channel); err != nil {
		zap.L().Debug("Failed to remove channel - already closed",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	if err := r.rpcClientMap.Remove(contextID); err != nil {
		zap.L().Warn("Failed to remove item from cache",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}
}

// ContextList returns the list of active context managed by the rpcwrapper
func (r *RPCWrapper) ContextList() []string {
	return r.contextList
}

// ProcessMessage checks if the given request is valid
func (r *RPCWrapper) ProcessMessage(req *Request, secret string) bool {

	return r.CheckValidity(req, secret)
}

// RegisterTypes  registers types that are exchanged between the controller and remoteenforcer
func RegisterTypes() {

	gob.RegisterName("github.com/aporeto-inc/enforcer/utils/rpcwrapper.Init_Request_Payload", *(&InitRequestPayload{}))
	gob.RegisterName("github.com/aporeto-inc/enforcer/utils/rpcwrapper.Init_Response_Payload", *(&InitResponsePayload{}))
	gob.RegisterName("github.com/aporeto-inc/enforcer/utils/rpcwrapper.Init_Supervisor_Payload", *(&InitSupervisorPayload{}))

	gob.RegisterName("github.com/aporeto-inc/enforcer/utils/rpcwrapper.Enforce_Payload", *(&EnforcePayload{}))
	gob.RegisterName("github.com/aporeto-inc/enforcer/utils/rpcwrapper.UnEnforce_Payload", *(&UnEnforcePayload{}))

	gob.RegisterName("github.com/aporeto-inc/enforcer/utils/rpcwrapper.Supervise_Request_Payload", *(&SuperviseRequestPayload{}))
	gob.RegisterName("github.com/aporeto-inc/enforcer/utils/rpcwrapper.UnSupervise_Payload", *(&UnSupervisePayload{}))
	gob.RegisterName("github.com/aporeto-inc/enforcer/utils/rpcwrapper.Stats_Payload", *(&StatsPayload{}))
}
