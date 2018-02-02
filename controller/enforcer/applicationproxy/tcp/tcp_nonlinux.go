// +build !linux

package tcp

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/controller/enforcer/connection"
	"github.com/aporeto-inc/trireme-lib/controller/enforcer/nfqdatapath/tokenaccessor"
	"github.com/aporeto-inc/trireme-lib/controller/enforcer/pucontext"
	"github.com/aporeto-inc/trireme-lib/controller/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/controller/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/controller/portset"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
)

const (
	sockOptOriginalDst = 80   //nolint
	proxyMarkInt       = 0x40 //Duplicated from supervisor/iptablesctrl refer to it

)

// Proxy maintains state for proxies connections from listen to backend.
type Proxy struct {
	// Listen Port to listen on
	Listen string
	// Backend address of the backend
	Backend string
	// certPath certificate path
	certPath string
	keyPath  string
	wg       sync.WaitGroup
	// Forward Should We forward connection
	Forward bool
	// Encrypt Is this connection encrypted
	Encrypt             bool
	mutualAuthorization bool
	tokenaccessor       tokenaccessor.TokenAccessor
	collector           collector.EventCollector
	contextTracker      cache.DataStore
	socketListeners     *cache.Cache
	// List of local IP's
	IPList []string
}

// proxyFlowProperties is a struct used to pass flow information up
type proxyFlowProperties struct {
	SourceIP   net.IP
	DestIP     net.IP
	SourcePort uint16
	DestPort   uint16
}

type socketListenerEntry struct {
	listen net.Listener
	port   string
}
type sockaddr struct {
	family uint16
	data   [14]byte
}

// NewProxy creates a new instance of proxy reate a new instance of Proxy
func NewProxy(listen string, forward bool, encrypt bool, tp tokenaccessor.TokenAccessor, c collector.EventCollector, contextTracker cache.DataStore, mutualAuthorization bool) *Proxy {

	return &Proxy{
		Forward:             forward,
		Encrypt:             encrypt,
		wg:                  sync.WaitGroup{},
		mutualAuthorization: mutualAuthorization,
		collector:           c,
		tokenaccessor:       tp,
		contextTracker:      contextTracker,
		socketListeners:     cache.NewCache("socketlisterner"),
		IPList:              []string{},
	}
}

func (p *Proxy) reportProxiedFlow(flowproperties *proxyFlowProperties, conn *connection.ProxyConnection, sourceID string, destID string, context *pucontext.PUContext, mode string, plc *policy.FlowPolicy) {

}

// Enforce is a dummy implementation of the enforcer.Enforcer for nonlinux compilers.
func (p *Proxy) Enforce(contextID string, puInfo *policy.PUInfo) error {
	return nil

}

// StartListener is a dummy implementation of the enforcer.Enforcer for nonlinux compilers.
func (p *Proxy) StartListener(contextID string, reterr chan error, port string) {
}

// Unenforce is a dummy implementation of the enforcer.Enforcer for nonlinux compilers.
func (p *Proxy) Unenforce(contextID string) error {

	return nil
}

// GetFilterQueue is a dummy implementation of the enforcer.Enforcer for nonlinux compilers.
func (p *Proxy) GetFilterQueue() *fqconfig.FilterQueue {
	return nil
}

// GetPortSetInstance is a dummy implementation of the enforcer.Enforcer for nonlinux compilers.
func (p *Proxy) GetPortSetInstance() portset.PortSet {
	return nil
}

// Run is a dummy implementation of the enforcer.Enforcer for nonlinux compilers.
func (p *Proxy) Run(ctx context.Context) error {
	return nil
}

// UpdateSecrets is a dummy implementation of the enforcer.Enforcer for nonlinux compilers.
func (p *Proxy) UpdateSecrets(secrets secrets.Secrets) error {

	return nil
}

// CompleteEndPointAuthorization is a dummy implementation of the enforcer.Enforcer for nonlinux compilers.
func (p *Proxy) CompleteEndPointAuthorization(backendip string, backendport uint16, upConn net.Conn, downConn int, contextID string) error {

	return nil
}

// StartClientAuthStateMachine is a dummy implementation of the enforcer.Enforcer for nonlinux compilers.
func (p *Proxy) StartClientAuthStateMachine(backendip string, backendport uint16, upConn net.Conn, downConn int, contextID string) error {

	return nil
}

// StartServerAuthStateMachine is a dummy implementation of the enforcer.Enforcer for nonlinux compilers.
func (p *Proxy) StartServerAuthStateMachine(backendip string, backendport uint16, upConn io.ReadWriter, downConn int, contextID string) error {

	return nil
}
