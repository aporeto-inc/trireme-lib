package rpcWrapper

import (
	"net/rpc"
	"time"

	"github.com/aporeto-inc/trireme/cache"
)

//RPCHdl exported
type RPCHdl struct {
	Client  *rpc.Client
	Channel string
}

var rpcClientMap = cache.NewCache(nil)

//NewRPCClient exported
//Will worry about locking later ... there is a small case where two callers
//call NewRPCClient from a different thread
func NewRPCClient(contextID string, channel string) *RPCHdl {
	//establish new connection to context/container
	client, err := rpc.DialHTTP("unix", channel)
	for err != nil {
		time.Sleep(10 * time.Millisecond)
		err = nil
		client, err = rpc.DialHTTP("unix", channel)
	}
	rpcClientMap.Add(contextID, &RPCHdl{Client: client, Channel: channel})
	return &RPCHdl{Client: client, Channel: channel}
}

//GetRPCClient exported
func GetRPCClient(contextID string) (*RPCHdl, error) {
	val, err := rpcClientMap.Get(contextID)
	if err == nil {
		return val.(*RPCHdl), err
	}
	return nil, err
}
