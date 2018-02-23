// +build !linux

package tcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
)

// Proxy is a mock proxy structure
type Proxy struct{}

// NewTCPProxy creates a new instance of proxy reate a new instance of Proxy
func NewTCPProxy(
	tp tokenaccessor.TokenAccessor,
	c collector.EventCollector,
	puFromID cache.DataStore,
	puContext string,
	certificate *tls.Certificate,
	caPool *x509.CertPool,
	exposedServices cache.DataStore,
	dependentServices cache.DataStore,
) *Proxy {
	return nil
}

// RunNetworkServer implements enforcer.Enforcer interface
func (p *Proxy) RunNetworkServer(ctx context.Context, listener net.Listener, encrypted bool) error {
	return nil
}

// ShutDown shuts it down
func (p *Proxy) ShutDown() error {
	return nil
}

// UpdateSecrets updates the secrets of the connections.
func (p *Proxy) UpdateSecrets(cert *tls.Certificate, caPool *x509.CertPool) {

}
