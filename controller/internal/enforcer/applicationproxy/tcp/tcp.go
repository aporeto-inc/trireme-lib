package tcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/blang/semver"
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/protomux"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/serviceregistry"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/tcp/verifier"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/tlshelper"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.uber.org/zap"
)

// Proxy maintains state for proxies connections from listen to backend.
type Proxy struct {
	collector      collector.EventCollector
	myControllerID string
	puID           string
	mark           int

	// TLS cert for the service
	certificate *tls.Certificate
	// caPool contains the system roots and in addition the services external CAs
	caPool *x509.CertPool

	// Verfier implements ID and IP ACL rules using the Peer Certificate Validation Handler
	verifier verifier.Verifier

	// List of local IP's
	localIPs map[string]struct{}

	agentVersion semver.Version

	sync.RWMutex
}

// NewTCPProxy creates a new instance of proxy reate a new instance of Proxy
func NewTCPProxy(
	c collector.EventCollector,
	puID string,
	certificate *tls.Certificate,
	caPool *x509.CertPool,
	agentVersion semver.Version,
	mark int,
) *Proxy {

	localIPs := markedconn.GetInterfaces()

	return &Proxy{
		collector:    c,
		puID:         puID,
		verifier:     verifier.New(caPool),
		localIPs:     localIPs,
		certificate:  certificate,
		caPool:       caPool,
		agentVersion: agentVersion,
		mark:         mark,
	}
}

// RunNetworkServer implements enforcer.Enforcer interface
func (p *Proxy) RunNetworkServer(
	ctx context.Context,
	listener net.Listener,
) error {

	go func() {
		for {
			select {
			case <-time.After(5 * time.Second):
				p.Lock()
				p.localIPs = markedconn.GetInterfaces()
				p.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()

	// Encryption is done transparently for TCP.
	go p.serve(ctx, listener)

	return nil
}

// UpdateSecrets updates the secrets of the connections.
func (p *Proxy) UpdateSecrets(
	cert *tls.Certificate,
	caPool *x509.CertPool,
	s secrets.Secrets,
	certPEM string,
	keyPEM string,
) {
	p.Lock()
	defer p.Unlock()

	p.certificate = cert
	p.caPool = caPool

	p.verifier.TrustCAs(caPool)
}

func (p *Proxy) serve(
	ctx context.Context,
	listener net.Listener,
) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if protoListener, ok := listener.(*protomux.ProtoListener); ok {
				// Windows: we don't really need the platform-specific data map for plain tcp (we can get it from the conn).
				// So just remove from the map here.
				markedconn.RemovePlatformData(protoListener.Listener, conn)
			}
			go p.handle(ctx, conn)
		}
	}
}

// ShutDown shuts down the server.
func (p *Proxy) ShutDown() error {
	return nil
}

func (p *Proxy) getService(
	ip net.IP,
	port int,
	local bool,
) (*policy.ApplicationService, error) {

	// If the destination is a local IP, it means that we are processing a client connection.
	if local {
		_, serviceData, err := serviceregistry.Instance().RetrieveDependentServiceDataByIDAndNetwork(p.puID, ip, port, "")
		if err != nil {
			return nil, fmt.Errorf("unknown dependent service pu:%s %s/%d: %s", p.puID, ip.String(), port, err)
		}
		return serviceData.ServiceObject, nil
	}

	portContext, err := serviceregistry.Instance().RetrieveExposedServiceContext(ip, port, "")
	if err != nil {
		return nil, fmt.Errorf("unknown exposed service %s/%d: %s", ip.String(), port, err)
	}
	return portContext.Service, nil
}

// handle handles a connection. upstream connection is the connection
// to the next hop while downstream connection is the client who
// initiated this connection.
// Client PU:
//   - upstream connection is from client to proxy.
//   - downstream connection is from proxy to the nexthop (service, LB, PU)
// Server PU:
//   - upstream connection is from client or another enforcer
//   - downstream connection is from proxy to the server nexthop
func (p *Proxy) handle(ctx context.Context, upConn net.Conn) {

	defer upConn.Close() // nolint

	// TODO: handle proxy protocol

	proxiedUpConn := upConn.(*markedconn.ProxiedConnection)
	ip, port := proxiedUpConn.GetOriginalDestination()
	platformData := proxiedUpConn.GetPlatformData()

	service, err := p.getService(ip, port, p.isLocal(upConn))
	if err != nil {
		zap.L().Error("no service found", zap.Error(err))
		return
	}

	puContext, err := p.puContextFromContextID(p.puID)
	if err != nil {
		zap.L().Error("no pu found", zap.String("puid", p.puID), zap.Error(err))
		return
	}

	p.handleWithPUAndService(ctx, upConn, ip, port, platformData, puContext, service)
}

func (p *Proxy) getPolicyReporter(
	puContext *pucontext.PUContext,
	sip net.IP,
	sport int,
	dip net.IP,
	dport int,
	service *policy.ApplicationService,
) *lookup {

	pfp := &proxyFlowProperties{
		myControllerID: p.myControllerID,
		DestIP:         dip.String(),
		DestPort:       uint16(dport),
		SourceIP:       sip.String(),
		SourcePort:     0, // TODO: Investigate if this should be set
		ServiceID:      service.ID,
		DestType:       collector.EndPointTypePU,
		SourceType:     collector.EndPointTypePU,
	}

	return &lookup{
		SourceIP:   sip,
		DestIP:     dip,
		SourcePort: uint16(sport),
		DestPort:   uint16(dport),
		collector:  p.collector,
		puContext:  puContext,
		pfp:        pfp,
	}
}

func (p *Proxy) handleWithPUAndService(
	ctx context.Context,
	upConn net.Conn,
	origDestIP net.IP,
	origDestPort int,
	platformData *markedconn.PlatformData,
	puContext *pucontext.PUContext,
	service *policy.ApplicationService,
) {
	// If we received connection isn't on private port, downstream connection has to be changed to
	// service listening port.
	downPort := origDestPort
	if downPort == service.PublicPort() {
		downPort = service.PrivatePort()
	}

	// Initialize a policy and reporting object
	src := upConn.RemoteAddr().(*net.TCPAddr)
	pr := p.getPolicyReporter(puContext, src.IP, src.Port, origDestIP, origDestPort, service)

	downConn, err := p.initiateDownstreamTCPConnection(ctx, origDestIP, downPort, platformData)
	if err != nil {
		// Report rejection
		pr.ReportStats(collector.EndPointTypeExternalIP, "", "default", collector.UnableToDial, nil, nil, false)
		return
	}
	defer downConn.Close() // nolint

	if err := p.proxyData(ctx, upConn, downConn, service, pr); err != nil {
		zap.L().Debug("Error with proxying data", zap.Error(err))
	}
}

func (p *Proxy) startEncryptedClientDataPath(
	ctx context.Context,
	downConn net.Conn,
	upConn net.Conn,
	service *policy.ApplicationService,
	pr *lookup,
) error {

	// Set a flag so policy engine knows if its on server or client
	pr.client = true

	// ServerName: Use first configured FQDN or the destination IP
	serverName, err := common.GetTLSServerName(downConn.RemoteAddr().String(), service)
	if err != nil {
		return fmt.Errorf("unable to get the server name: %s", err)
	}

	// Encrypt Down Connection
	p.RLock()
	ca := p.caPool
	certs := []tls.Certificate{}
	if p.certificate != nil {
		certs = append(certs, *p.certificate)
	}
	p.RUnlock()

	t, err := getClientTLSConfig(ca, certs, serverName, service.External)
	if err != nil {
		return fmt.Errorf("unable to generate tls configuration: %s", err)
	}

	t.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		return p.verifier.VerifyPeerCertificate(rawCerts, verifiedChains, pr, false)
	}

	// Do TLS
	tlsConn := tls.Client(downConn, t)
	defer tlsConn.Close() // nolint errcheck
	downConn = tlsConn

	zap.L().Debug(
		"Handle client connection",
		zap.String("src", upConn.RemoteAddr().String()),
		zap.String("dst", downConn.RemoteAddr().String()),
		zap.String("tls.server", t.ServerName),
		zap.Bool("tls.rootCAs", t.RootCAs != nil),
		zap.Int("tls.certs", len(t.Certificates)),
	)

	// TLS will automatically start negotiation on write. Nothing to do for us.
	p.copyData(ctx, upConn, downConn)
	return nil
}

func (p *Proxy) startEncryptedServerDataPath(
	ctx context.Context,
	downConn net.Conn,
	upConn net.Conn,
	service *policy.ApplicationService,
	pr *lookup,
) error {

	zap.L().Debug(
		"Handle server connection",
		zap.String("src", upConn.RemoteAddr().String()),
		zap.String("dst", downConn.RemoteAddr().String()),
		zap.String("orig-dst", pr.DestIP.String()),
		zap.Uint16("orig-dstport", pr.DestPort),
	)

	if service.PrivateTLSListener {
		zap.L().Debug("convert connection to server as TLS")
		downConn = tls.Client(downConn, &tls.Config{
			InsecureSkipVerify: true,
		})
	}

	proxiedUpConn := upConn.(*markedconn.ProxiedConnection)
	_, originalPort := proxiedUpConn.GetOriginalDestination()

	// Use Aporeto certs
	p.RLock()
	caPool := p.caPool
	clientCerts := []tls.Certificate{}
	if p.certificate != nil {
		clientCerts = []tls.Certificate{*p.certificate}
	}
	p.RUnlock()

	tlsConfig, err := getServerTLSConfig(
		caPool,
		clientCerts,
		originalPort,
		service,
	)
	if err != nil {
		return fmt.Errorf("invalid tls server configuration: %s", err)
	}

	if tlsConfig != nil {
		// Register Peer Certificate Verification so we can apply policies.
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return p.verifier.VerifyPeerCertificate(rawCerts, verifiedChains, pr, tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert)
		}

		tlsConn := tls.Server(upConn.(*markedconn.ProxiedConnection).GetTCPConnection(), tlsConfig)
		defer tlsConn.Close() // nolint errcheck

		// Manually initiating the TLS handshake to get the connection state.
		// The call to write will skip TLS handshake.
		if err := tlsConn.Handshake(); err != nil {
			return err
		}

		if pingEnabled(tlsConn) {
			return p.processPingRequest(tlsConn, pr)
		}

		upConn = tlsConn
	} else {
		// In case of no TLS, apply IP policies right here.
		action := pr.IPLookup()
		zap.L().Debug("ip acl lookup", zap.Bool("action", action))
		if !action {
			return fmt.Errorf("ip acl drop")
		}
	}

	// TLS will automatically start negotiation on write. Nothing to for us.
	p.copyData(ctx, upConn, downConn)
	return nil
}

func (p *Proxy) copyData(
	ctx context.Context,
	source, dest net.Conn,
) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		dataprocessor(ctx, source, dest)
		wg.Done()
	}()
	go func() {
		dataprocessor(ctx, dest, source)
		wg.Done()
	}()
	wg.Wait()
}

type readwithContext func(p []byte) (n int, err error)

func (r readwithContext) Read(p []byte) (int, error) { return r(p) }

func dataprocessor(
	ctx context.Context,
	source net.Conn,
	dest net.Conn,
) { // nolint
	defer func() {
		switch connType := dest.(type) {
		case *tls.Conn:
			connType.CloseWrite() // nolint errcheck
		case *net.TCPConn:
			connType.CloseWrite() // nolint errcheck
		case *markedconn.ProxiedConnection:
			connType.GetTCPConnection().CloseWrite() // nolint errcheck
		}
	}()

	if _, err := io.Copy(dest, readwithContext(
		func(p []byte) (int, error) {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			default:
				return source.Read(p)
			}
		},
	),
	); err != nil { // nolint
		logErr(err)
	}
}

func (p *Proxy) proxyData(
	ctx context.Context,
	upConn net.Conn,
	downConn net.Conn,
	service *policy.ApplicationService,
	pr *lookup,
) error {

	// If the destination is not a local IP, it means that we are processing a client connection.
	if p.isLocal(upConn) {
		return p.startEncryptedClientDataPath(ctx, downConn, upConn, service, pr)
	}

	return p.startEncryptedServerDataPath(ctx, downConn, upConn, service, pr)
}

func (p *Proxy) puContextFromContextID(
	puID string,
) (*pucontext.PUContext, error) {

	sctx, err := serviceregistry.Instance().RetrieveServiceByID(puID)
	if err != nil {
		return nil, fmt.Errorf("Context not found %s", puID)
	}

	return sctx.PUContext, nil
}

// initiateDownstreamTCPConnection initiates a downstream TCP connection
func (p *Proxy) initiateDownstreamTCPConnection(
	ctx context.Context,
	ip net.IP,
	port int,
	platformData *markedconn.PlatformData,
) (net.Conn, error) {

	raddr := &net.TCPAddr{
		IP:   ip,
		Port: port,
	}
	return markedconn.DialMarkedWithContext(ctx, "tcp", raddr.String(), platformData, p.mark)
}

func (p *Proxy) isLocal(conn net.Conn) bool {

	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return false
	}

	p.RLock()
	defer p.RUnlock()

	if _, ok := p.localIPs[host]; ok {
		return true
	}
	return false
}

func logErr(err error) bool {
	switch err.(type) {
	case syscall.Errno:
		zap.L().Error("Connection error to destination", zap.Error(err))
	default:
		zap.L().Error("Connection terminated", zap.Error(err))
	}
	return false
}

// getPublicServerTLSConfig provides the TLS configuration for the public port.
// There is a valid case where we dont provide TLS configuration (nil) but error
// is also nil to support the case of publicly exposed port.
func getPublicServerTLSConfig(
	caPool *x509.CertPool,
	clientCerts []tls.Certificate,
	service *policy.ApplicationService,
) (t *tls.Config, err error) {

	// Apply Public configuration
	if (service.PublicServiceTLSType != policy.ServiceTLSTypeCustom) && (service.PublicServiceTLSType != policy.ServiceTLSTypeAporeto) {
		return nil, nil
	}

	t = tlshelper.NewBaseTLSServerConfig()

	// Server Cert and Key.
	if service.PublicServiceTLSType == policy.ServiceTLSTypeCustom {
		// Use custom certs
		if len(service.PublicServiceCertificate) > 0 && len(service.PublicServiceCertificateKey) > 0 {

			cert, err := tls.X509KeyPair(service.PublicServiceCertificate, service.PublicServiceCertificateKey)
			if err != nil {
				return nil, fmt.Errorf("invalid public cert pair")
			}
			t.Certificates = []tls.Certificate{cert}
		}
	} else if service.PublicServiceTLSType == policy.ServiceTLSTypeAporeto {
		// Use Aporeto certs
		t.Certificates = clientCerts
	}

	// mTLS with client
	if service.UserAuthorizationType == policy.UserAuthorizationMutualTLS {
		t.ClientAuth = tls.RequireAndVerifyClientCert
		t.ClientCAs = caPool
		if len(service.MutualTLSTrustedRoots) > 0 {
			if !t.ClientCAs.AppendCertsFromPEM(service.MutualTLSTrustedRoots) {
				return nil, fmt.Errorf("Unable to process client CAs")
			}
		}
	}

	return t, nil
}

// getExposedServerMTLSConfig provides the mTLS configuration for the server.
func getExposedServerMTLSConfig(
	caPool *x509.CertPool,
	certs []tls.Certificate,
) (t *tls.Config, err error) {

	if len(certs) == 0 {
		return nil, fmt.Errorf("Failed to start encryption")
	}

	t = tlshelper.NewBaseTLSServerConfig()
	t.Certificates = certs
	t.ClientCAs = caPool
	t.ClientAuth = tls.RequireAndVerifyClientCert
	return t, nil
}

// getServerTLSConfig provides the server TLS configuration. It handles the
// server on public and exposed ports.
// returns:
//    - error
//    - tls.Config which can be nil even when error is nil to indicate no TLS
func getServerTLSConfig(
	caPool *x509.CertPool,
	certs []tls.Certificate,
	originalPort int,
	service *policy.ApplicationService,
) (t *tls.Config, err error) {

	if originalPort != service.PublicPort() {
		// mTLS for Up Connection for exposed ports protected by Aporeto
		return getExposedServerMTLSConfig(caPool, certs)
	}
	// TLS configuration supported on public ports
	return getPublicServerTLSConfig(caPool, certs, service)
}

// getTLSConfig generates a tls.Config for a given client based on the service it may be accessing.
// - Services protected by Aporeto should do mTLS.
// - External (Third Party) Services do TLS only.
func getClientTLSConfig(
	caPool *x509.CertPool,
	clientCerts []tls.Certificate,
	serverName string,
	external bool,
) (t *tls.Config, err error) {

	t = tlshelper.NewBaseTLSClientConfig()
	t.RootCAs = caPool
	t.ServerName = serverName

	if !external {
		if len(clientCerts) == 0 {
			return nil, fmt.Errorf("no client certs provided for mTLS")
		}
		// Do mTLS enforcer protected services. TLS for external service.
		t.Certificates = clientCerts
	}
	return t, nil
}
