// Package multitls implements a listener which can serve different TLS servers depending on their original destination.
// A connection might be meant for the public application port or for the normal service port. With this listener here
// we can serve different TLS servers on the same listener/port by just inspecting the connection.
package multitls

import (
	"crypto/tls"
	"errors"
	"net"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
)

// ensure that Listener implements net.Listener
var _ net.Listener = &Listener{}

// InvalidConnErr will be returned when the accepted connection is not a ProxiedConnection
var InvalidConnErr = errors.New("multitls: invalid connection, connection must be of type ProxiedConnection")

type Listener struct {
	net.Listener
	publicPort int
	internal   *tls.Config
	public     *tls.Config
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

	if l.publicPort > 0 {
		_, port := mc.GetOriginalDestination()
		if l.publicPort == port {
			return tls.Server(mc, l.public), nil
		}
	}

	// in any other case we return the
	return tls.Server(mc, l.internal), nil
}

// NewMultiTLSListener will create a new multi TLS listener.
func NewMultiTLSListener(l net.Listener, publicPort int, internal, public *tls.Config) *Listener {
	return &Listener{
		Listener:   l,
		publicPort: publicPort,
		internal:   internal,
		public:     public,
	}
}
