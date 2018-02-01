package rpcwrapper

import (
	"testing"
	"time"
)

//Not mocking system libraries
//Will create actual rpc client server without using wrapper to test our implementations

const (
	defaultchannel = "/tmp/test.sock"
)

// TestNewRPCClient mocks an RPC client test
func TestNewRPCClient(t *testing.T) {

	//Test without  a rpc server
	rpchdl := NewRPCWrapper()
	resp := make(chan error, 1)
	go asyncRpcclient(defaultchannel, resp, rpchdl)
	select {
	case r := <-resp:
		if r == nil {
			t.Errorf("SUCCESS in the absence of rpc server")
		}
	case <-time.After(1 * time.Second):
		t.Errorf("RPCClient blocked and does not return")

	}
	err := rpchdl.NewRPCClient("12345", defaultchannel, "mysecret")
	if err == nil {
		t.Errorf("No error returned when there is not server")
	}

}
