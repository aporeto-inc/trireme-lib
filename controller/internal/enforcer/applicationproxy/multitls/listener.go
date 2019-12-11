// Package multitls implements a listener which can serve different TLS servers depending on their original destination.
// A connection might be meant for the public application port or for the normal service port. With this listener here
// we can serve different TLS servers on the same listener/port by just inspecting the connection.
package multitls

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/serviceregistry"
)

// ensure that Listener implements net.Listener
var _ net.Listener = &Listener{}

var (
	// InvalidListenerErr will be returned in NewMultiTLSListener if the provided listener is not a ProxiedListener
	InvalidListenerErr = errors.New("multitls: invalid listener, listener must be of type ProxiedListener")

	// InvalidConnErr will be returned when the accepted connection is not a ProxiedConnection
	InvalidConnErr = errors.New("multitls: invalid connection, connection must be of type ProxiedConnection")
)

type Listener struct {
	net.Listener
	registry *serviceregistry.Registry
	internal *tls.Config
	public   *tls.Config
}

// Accept waits for and returns the next connection to the listener.
func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	mc, ok := c.(*markedconn.ProxiedConnection)
	if !ok {
		return nil, InvalidConnErr
	}

	ip, port := mc.GetOriginalDestination()
	pc, err := l.registry.RetrieveExposedServiceContext(ip, port, "")
	if err != nil {
		return nil, fmt.Errorf("multitls: unknown service: %s", err)
	}

	if pc.Service == nil {
		return nil, fmt.Errorf("multitls: empty service")
	}

	if pc.Service.PublicNetworkInfo != nil && pc.Service.PublicNetworkInfo.Ports != nil {
		publicPort, err := pc.Service.PublicNetworkInfo.Ports.SinglePort()
		if err != nil {
			return nil, fmt.Errorf("multitls: service public port: %s", err)
		}
		if publicPort == uint16(port) {
			return tls.Server(mc, l.public), nil
		}
	}

	// in any other case we return the
	return tls.Server(mc, l.internal), nil
}

// NewMultiTLSListener will create a new multi TLS listener.
func NewMultiTLSListener(l net.Listener, registry *serviceregistry.Registry, internal, public *tls.Config) (net.Listener, error) {
	if _, ok := l.(*markedconn.ProxiedListener); !ok {
		return nil, InvalidListenerErr
	}

	return &Listener{
		Listener: l,
		registry: registry,
		internal: internal,
		public:   public,
	}, nil
}
