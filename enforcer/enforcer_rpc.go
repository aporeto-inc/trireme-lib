package enforcer

import (
	"net/rpc"

	"github.com/aporeto-inc/trireme/enforcer_adaptor"
)

type RPC_handler struct {
	Rpc_client *rpc.Client
}

const (
	// Defaults used by HandleHTTP
	DefaultRPCPath   = "/_goRPC_"
	DefaultDebugPath = "/debug/rpc"
)

func (r *RPC_handler) ProcessMessage(req *enforcer_adaptor.Enforcer_request, resp *enforcer_adaptor.Enforcer_response) error {
	return nil
}

func NewRPC_handler(path string) (*RPC_handler, error) {
	rpc_hdl := new(RPC_handler)
	client, _ := rpc.DialHTTP("unix", path)
	if client == nil {
	}
	rpc_hdl.Rpc_client = client
	return rpc_hdl, nil
}
