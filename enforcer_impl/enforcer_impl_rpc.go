package enforcer_impl

import (
	"net"
	"net/http"
	"net/rpc"

	"github.com/aporeto-inc/trireme/enforcer_adaptor"
)

type RPC_handler struct{}

const (
	// Defaults used by HandleHTTP
	DefaultRPCPath   = "/_goRPC_"
	DefaultDebugPath = "/debug/rpc"
)

func (r *RPC_handler) ProcessMessage(req *enforcer_adaptor.Enforcer_request, resp *enforcer_adaptor.Enforcer_response) error {
	return nil
}

func NewRPC_handler(path string) error {
	rpc_hdl := new(RPC_handler)
	server := rpc.NewServer()
	server.RegisterName("server", rpc_hdl)
	server.HandleHTTP(DefaultRPCPath, DefaultDebugPath)
	listen, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	go http.Serve(listen, nil)
	return nil
}
