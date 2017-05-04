// +build !linux

package remoteenforcer

import (
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
)

// Server is a fake implementation for building on darwin.
type Server struct {
}

// EnforcerExit is a fake implementation for building on darwin.
func (s *Server) EnforcerExit(req rpcwrapper.Request, resp *rpcwrapper.Response) error { return nil }

// NewServer is a fake implementation for building on darwin.
func NewServer(service enforcer.PacketProcessor, rpchdl rpcwrapper.RPCServer, pcchan string, secret string) (*Server, error) {
	return nil, nil
}

// LaunchRemoteEnforcer is a fake implementation for building on darwin.
func LaunchRemoteEnforcer(service enforcer.PacketProcessor) error { return nil }
