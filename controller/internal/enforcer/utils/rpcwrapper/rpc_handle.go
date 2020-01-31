package rpcwrapper

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/mitchellh/mapstructure"

	"github.com/mitchellh/hashstructure"
	"github.com/ugorji/go/codec"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

// RPCHdl is a per client handle
type RPCHdl struct {
	Client  *rpc.Client
	Channel string
	Secret  string
}

// RPCWrapper  is a struct which holds stats for all rpc sesions
type RPCWrapper struct {
	rpcClientMap  *cache.Cache
	msgpackHandle *msgpackHandle
	sync.Mutex
}

// NewRPCWrapper creates a new rpcwrapper
func NewRPCWrapper() *RPCWrapper {

	return &RPCWrapper{
		rpcClientMap:  cache.NewCache("RPCWrapper"),
		msgpackHandle: newMsgpackHandle(),
	}
}

const (
	maxRetries     = 10000
	envRetryString = "REMOTE_RPCRETRIES"
)

// NewRPCClient exported
func (r *RPCWrapper) NewRPCClient(contextID string, channel string, sharedsecret string) error {

	r.Lock()
	defer r.Unlock()

	max := maxRetries
	retries := os.Getenv(envRetryString)
	if len(retries) > 0 {
		max, _ = strconv.Atoi(retries)
	}

	numRetries := 0
	conn, err := net.Dial("unix", channel)
	for err != nil {
		numRetries++
		if numRetries >= max {
			return err
		}

		time.Sleep(5 * time.Millisecond)
		conn, err = net.Dial("unix", channel)
	}

	// Custom msgpack client codec
	rpcCodec := codec.MsgpackSpecRpc.ClientCodec(conn, r.msgpackHandle.handler())
	client := rpc.NewClientWithCodec(rpcCodec)

	r.rpcClientMap.AddOrUpdate(contextID, &RPCHdl{Client: client, Channel: channel, Secret: sharedsecret})

	return nil

}

// GetRPCClient gets a handle to the rpc client for the contextID( enforcer in the container)
func (r *RPCWrapper) GetRPCClient(contextID string) (*RPCHdl, error) {

	r.Lock()
	defer r.Unlock()

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
	data := map[string]interface{}{}
	mapstructure.Decode(req.Payload.(*InitRequestPayload), &data)
	fmt.Println("DATA", data)
	hash, err := payloadHash(data)
	if err != nil {
		return err
	}

	if _, err := digest.Write(hash); err != nil {
		return err
	}

	req.HashAuth = digest.Sum(nil)

	return rpcClient.Client.Call(methodName, req, resp)
}

// CheckValidity checks if the received message is valid
func (r *RPCWrapper) CheckValidity(req *Request, secret string) bool {

	digest := hmac.New(sha256.New, []byte(secret))

	hash, err := payloadHash(req.Payload)
	if err != nil {
		return false
	}

	if _, err := digest.Write(hash); err != nil {
		return false
	}

	return hmac.Equal(req.HashAuth, digest.Sum(nil))
}

//NewRPCServer returns an interface RPCServer
func NewRPCServer() RPCServer {

	return &RPCWrapper{
		msgpackHandle: newMsgpackHandle(),
	}
}

// StartServer Starts a server and waits for new connections this function never returns
func (r *RPCWrapper) StartServer(ctx context.Context, protocol string, path string, handler interface{}) error {

	if len(path) == 0 {
		zap.L().Fatal("Sock param not passed in environment")
	}

	// Register handlers
	if err := rpc.Register(handler); err != nil {
		return err
	}
	rpc.HandleHTTP()

	// removing old path in case it exists already - error if we can't remove it
	if _, err := os.Stat(path); err == nil {

		zap.L().Debug("Socket path already exists: removing", zap.String("path", path))

		if rerr := os.Remove(path); rerr != nil {
			return fmt.Errorf("unable to delete existing socket path %s: %s", path, rerr)
		}
	}

	// Get listener
	listen, err := net.Listen(protocol, path)
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := listen.Accept()
			if err != nil {
				zap.L().Error("unable to accept connection: %v", zap.Error(err))
				continue
			}

			rpcCodec := codec.MsgpackSpecRpc.ServerCodec(conn, r.msgpackHandle.handler())
			rpc.ServeCodec(rpcCodec)
		}
	}()

	<-ctx.Done()

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
	r.Lock()
	defer r.Unlock()

	rpcHdl, err := r.rpcClientMap.Get(contextID)
	if err != nil {
		return
	}

	if err = rpcHdl.(*RPCHdl).Client.Close(); err != nil {
		zap.L().Warn("Failed to close channel",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	if err = os.Remove(rpcHdl.(*RPCHdl).Channel); err != nil {
		zap.L().Debug("Failed to remove channel - already closed",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}

	if err = r.rpcClientMap.Remove(contextID); err != nil {
		zap.L().Warn("Failed to remove item from cache",
			zap.String("contextID", contextID),
			zap.Error(err),
		)
	}
}

// ContextList returns the list of active context managed by the rpcwrapper
func (r *RPCWrapper) ContextList() []string {
	keylist := r.rpcClientMap.KeyList()
	contextArray := []string{}
	for _, key := range keylist {
		if kstring, ok := key.(string); ok {
			contextArray = append(contextArray, kstring)
		}
	}
	return contextArray
}

// ProcessMessage checks if the given request is valid
func (r *RPCWrapper) ProcessMessage(req *Request, secret string) bool {

	return r.CheckValidity(req, secret)
}

// payloadHash returns the has of the payload
func payloadHash(payload interface{}) ([]byte, error) {
	hash, err := hashstructure.Hash(payload, nil)
	if err != nil {
		return []byte{}, err
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, hash)
	return buf, nil
}
