// +build darwin !linux

package remoteenforcer

import (
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"

	log "github.com/Sirupsen/logrus"
)

// Server is a fake implementation for building on darwin.
type Server struct{}

// EnforcerExit is a fake implementation for building on darwin.
func (s *Server) EnforcerExit(req rpcwrapper.Request, resp *rpcwrapper.Response) error { return nil }

// NewServer is a fake implementation for building on darwin.
func NewServer(service enforcer.PacketProcessor, rpcchan string, secret string) *Server { return nil }

// LaunchRemoteEnforcer is a fake implementation for building on darwin.
func LaunchRemoteEnforcer(service enforcer.PacketProcessor, logLevel log.Level) {}
