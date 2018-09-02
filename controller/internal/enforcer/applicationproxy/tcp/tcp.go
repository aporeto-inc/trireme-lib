package tcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/connproc"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
)

const (
	proxyMarkInt = 0x40 //Duplicated from supervisor/iptablesctrl refer to it
)

// Proxy maintains state for proxies connections from listen to backend.
type Proxy struct {
	tokenaccessor tokenaccessor.TokenAccessor
	collector     collector.EventCollector

	puContext string
	puFromID  cache.DataStore
	portCache map[int]string

	certificate *tls.Certificate
	ca          *x509.CertPool

	// List of local IP's
	localIPs map[string]struct{}

	sync.RWMutex
}

// proxyFlowProperties is a struct used to pass flow information up
type proxyFlowProperties struct {
	SourceIP   string
	DestIP     string
	PolicyID   string
	ServiceID  string
	DestType   collector.EndPointType
	SourceType collector.EndPointType
	SourcePort uint16
	DestPort   uint16
}

// NewTCPProxy creates a new instance of proxy reate a new instance of Proxy
func NewTCPProxy(
	tp tokenaccessor.TokenAccessor,
	c collector.EventCollector,
	puFromID cache.DataStore,
	puContext string,
	certificate *tls.Certificate,
	caPool *x509.CertPool,
) *Proxy {

	localIPs := connproc.GetInterfaces()

	return &Proxy{
		collector:     c,
		tokenaccessor: tp,
		puFromID:      puFromID,
		puContext:     puContext,
		localIPs:      localIPs,
		certificate:   certificate,
		ca:            caPool,
	}
}

// RunNetworkServer implements enforcer.Enforcer interface
func (p *Proxy) RunNetworkServer(ctx context.Context, listener net.Listener, encrypted bool) error {

	// Encryption is done transparently for TCP.
	go p.serve(ctx, listener)

	return nil
}

// UpdateSecrets updates the secrets of the connections.
func (p *Proxy) UpdateSecrets(cert *tls.Certificate, caPool *x509.CertPool, s secrets.Secrets, certPEM, keyPEM string) {
	p.Lock()
	defer p.Unlock()

	p.certificate = cert
	p.ca = caPool
}

func (p *Proxy) serve(ctx context.Context, listener net.Listener) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go p.handle(ctx, conn)
		}
	}
}

// ShutDown shuts down the server.
func (p *Proxy) ShutDown() error {
	return nil
}

// UpdatePortCache updates the port cache
func (p *Proxy) UpdatePortCache(portCache map[int]string) {
	p.Lock()
	defer p.Unlock()
	p.portCache = portCache
}

// handle handles a connection
func (p *Proxy) handle(ctx context.Context, upConn net.Conn) {
	defer upConn.Close() // nolint

	ip, port := upConn.(*markedconn.ProxiedConnection).GetOriginalDestination()

	downConn, err := p.downConnection(ip, port)
	if err != nil {
		flowproperties := &proxyFlowProperties{
			DestIP:     ip.String(),
			DestPort:   uint16(port),
			SourceIP:   upConn.RemoteAddr().(*net.TCPAddr).IP.String(),
			DestType:   collector.EndPointTypeExternalIP,
			SourceType: collector.EnpointTypePU,
		}

		puContext, perr := p.puContextFromContextID(p.puContext)
		if perr != nil {
			zap.L().Error("Unable to find policy context for tcp connection",
				zap.String("Context", p.puContext),
				zap.Error(perr))
			return
		}

		p.reportRejectedFlow(flowproperties, puContext.ManagementID(), "default", puContext, collector.UnableToDial, nil, nil)
		return
	}
	defer downConn.Close() // nolint

	// Now let us handle the state machine for the down connection
	isEncrypted, err := p.CompleteEndPointAuthorization(ip, port, upConn, downConn)
	if err != nil {
		zap.L().Error("Error on Authorization", zap.Error(err))
		return
	}

	if isEncrypted {
		if err := p.handleEncryptedData(ctx, upConn, downConn, ip); err != nil {
			zap.L().Error("Failed to process connection - aborting", zap.Error(err))
		}
		return
	}

	if err := connproc.Pipe(ctx, upConn, downConn); err != nil {
		zap.L().Error("Failed to handle data pipe - aborting", zap.Error(err))
	}
}

func (p *Proxy) startEncryptedClientDataPath(ctx context.Context, downConn net.Conn, serverConn net.Conn, ip net.IP) error {

	p.RLock()
	ca := p.ca
	p.RUnlock()

	tlsConn := tls.Client(downConn, &tls.Config{
		InsecureSkipVerify: true,
		ClientCAs:          ca,
	})
	defer tlsConn.Close() // nolint errcheck

	// TLS will automatically start negotiation on write. Nothing to do for us.
	p.copyData(ctx, serverConn, tlsConn)
	return nil
}

func (p *Proxy) startEncryptedServerDataPath(ctx context.Context, downConn net.Conn, serverConn net.Conn) error {

	p.RLock()
	certs := []tls.Certificate{*p.certificate}
	p.RUnlock()

	tlsConn := tls.Server(serverConn.(*markedconn.ProxiedConnection).GetTCPConnection(), &tls.Config{
		Certificates: certs,
	})
	defer tlsConn.Close() // nolint errcheck

	// TLS will automatically start negotiation on write. Nothing to for us.
	p.copyData(ctx, tlsConn, downConn)
	return nil
}

func (p *Proxy) copyData(ctx context.Context, source, dest net.Conn) {
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

func dataprocessor(ctx context.Context, source, dest net.Conn) { // nolint
	defer func() {
		switch dest.(type) {
		case *tls.Conn:
			dest.(*tls.Conn).CloseWrite() // nolint errcheck
		case *net.TCPConn:
			dest.(*net.TCPConn).CloseWrite() // nolint errcheck
		case *markedconn.ProxiedConnection:
			dest.(*markedconn.ProxiedConnection).GetTCPConnection().CloseWrite() // nolint errcheck
		}
	}()

	if _, err := io.Copy(dest, readwithContext(func(p []byte) (int, error) {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
			return source.Read(p)
		}
	})); err != nil { // nolint
		logErr(err)
	}
}

func (p *Proxy) handleEncryptedData(ctx context.Context, upConn net.Conn, downConn net.Conn, ip net.IP) error {
	// If the destination is not a local IP, it means that we are processing a client connection.
	if _, ok := p.localIPs[ip.String()]; !ok {
		return p.startEncryptedClientDataPath(ctx, downConn, upConn, ip)
	}
	return p.startEncryptedServerDataPath(ctx, downConn, upConn)
}

func (p *Proxy) puContextFromContextID(puID string) (*pucontext.PUContext, error) {

	ctx, err := p.puFromID.Get(puID)
	if err != nil {
		return nil, fmt.Errorf("Context not found %s", puID)
	}

	puContext, ok := ctx.(*pucontext.PUContext)
	if !ok {
		return nil, fmt.Errorf("Context not converted %s", puID)
	}

	return puContext, nil
}

// Initiate the downstream connection
func (p *Proxy) downConnection(ip net.IP, port int) (net.Conn, error) {

	raddr := &net.TCPAddr{
		IP:   ip,
		Port: port,
	}

	return markedconn.DialMarkedTCP("tcp", nil, raddr, proxyMarkInt)

}

// CompleteEndPointAuthorization -- Aporeto Handshake on top of a completed connection
// We will define states here equivalent to SYN_SENT AND SYN_RECEIVED
func (p *Proxy) CompleteEndPointAuthorization(downIP net.IP, downPort int, upConn, downConn net.Conn) (bool, error) {

	backendip := downIP.String()

	// If the backend is not a local IP it means that we are a client.
	if _, ok := p.localIPs[backendip]; !ok {
		return p.StartClientAuthStateMachine(downIP, downPort, downConn)
	}

	isEncrypted, err := p.StartServerAuthStateMachine(downIP, downPort, upConn)
	if err != nil {
		return false, err
	}

	return isEncrypted, nil
}

//StartClientAuthStateMachine -- Starts the aporeto handshake for client application
func (p *Proxy) StartClientAuthStateMachine(downIP net.IP, downPort int, downConn net.Conn) (bool, error) {
	// We are running on top of TCP nothing should be lost or come out of order makes the state machines easy....
	puContext, err := p.puContextFromContextID(p.puContext)
	if err != nil {
		return false, fmt.Errorf("Cannot find policy context: %s", err)
	}
	isEncrypted := false
	conn := connection.NewProxyConnection()

	flowproperties := &proxyFlowProperties{
		DestIP:     downIP.String(),
		DestPort:   uint16(downPort),
		SourceIP:   downConn.LocalAddr().(*net.TCPAddr).IP.String(),
		DestType:   collector.EndPointTypeExternalIP,
		SourceType: collector.EnpointTypePU,
	}

	defer downConn.SetDeadline(time.Time{}) // nolint errcheck

	// First validate that L3 policies do not require a reject.
	networkReport, networkPolicy, noNetAccessPolicy := puContext.ApplicationACLPolicyFromAddr(downIP.To4(), uint16(downPort))
	if noNetAccessPolicy == nil && networkPolicy.Action.Rejected() {
		p.reportRejectedFlow(flowproperties, puContext.ManagementID(), networkPolicy.ServiceID, puContext, collector.PolicyDrop, networkReport, networkPolicy)
		return false, fmt.Errorf("Unauthorized by Application ACLs")
	}

	for {
		switch conn.GetState() {
		case connection.ClientTokenSend:
			if err := downConn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return false, err
			}
			token, err := p.tokenaccessor.CreateSynPacketToken(puContext, &conn.Auth)
			if err != nil {
				return isEncrypted, fmt.Errorf("unable to create syn token: %s", err)
			}
			if n, err := writeMsg(downConn, token); err != nil || n < len(token) {
				return isEncrypted, fmt.Errorf("unable to send auth token: %s", err)
			}
			conn.SetState(connection.ClientPeerTokenReceive)

		case connection.ClientPeerTokenReceive:
			if err := downConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return false, err
			}
			msg, err := readMsg(downConn)
			if err != nil {
				return false, fmt.Errorf("Failed to read peer token: %s", err)
			}
			claims, err := p.tokenaccessor.ParsePacketToken(&conn.Auth, msg)
			if err != nil || claims == nil {
				p.reportRejectedFlow(flowproperties, puContext.ManagementID(), collector.DefaultEndPoint, puContext, collector.InvalidToken, nil, nil)
				return false, fmt.Errorf("peer token reject because of bad claims: error: %s, claims: %v %v", err, claims, string(msg))
			}
			report, packet := puContext.SearchTxtRules(claims.T, false)
			if packet.Action.Rejected() {
				p.reportRejectedFlow(flowproperties, puContext.ManagementID(), conn.Auth.RemoteContextID, puContext, collector.PolicyDrop, report, packet)
				return isEncrypted, errors.New("dropping because of reject rule on transmitter")
			}
			if packet.Action.Encrypted() {
				isEncrypted = true
			}
			conn.SetState(connection.ClientSendSignedPair)

		case connection.ClientSendSignedPair:
			if err := downConn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return false, err
			}
			token, err := p.tokenaccessor.CreateAckPacketToken(puContext, &conn.Auth)
			if err != nil {
				return isEncrypted, fmt.Errorf("unable to create ack token: %s", err)
			}
			if n, err := writeMsg(downConn, token); err != nil || n < len(token) {
				return isEncrypted, fmt.Errorf("unable to send ack: %s", err)
			}
			return isEncrypted, nil
		}
	}
}

// StartServerAuthStateMachine -- Start the aporeto handshake for a server application
func (p *Proxy) StartServerAuthStateMachine(ip fmt.Stringer, backendport int, upConn net.Conn) (bool, error) {

	puContext, err := p.puContextFromContextID(p.puContext)
	if err != nil {
		return false, err
	}
	isEncrypted := false

	flowProperties := &proxyFlowProperties{
		DestIP:     ip.String(),
		DestPort:   uint16(backendport),
		SourceIP:   getIP(upConn),
		ServiceID:  p.portCache[backendport],
		DestType:   collector.EnpointTypePU,
		SourceType: collector.EnpointTypePU,
	}
	conn := connection.NewProxyConnection()
	conn.SetState(connection.ServerReceivePeerToken)

	// First validate that L3 policies do not require a reject.
	networkReport, networkPolicy, noNetAccessPolicy := puContext.NetworkACLPolicyFromAddr(upConn.RemoteAddr().(*net.TCPAddr).IP.To4(), uint16(backendport))
	if noNetAccessPolicy == nil && networkPolicy.Action.Rejected() {
		flowProperties.SourceType = collector.EndPointTypeExternalIP
		p.reportRejectedFlow(flowProperties, networkPolicy.ServiceID, puContext.ManagementID(), puContext, collector.PolicyDrop, networkReport, networkPolicy)
		return false, fmt.Errorf("Unauthorized by Network ACLs")
	}

	defer upConn.SetDeadline(time.Time{}) // nolint errcheck

	for {
		if err := upConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return false, err
		}

		switch conn.GetState() {
		case connection.ServerReceivePeerToken:
			if err := upConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return false, err
			}
			msg, err := readMsg(upConn)
			if err != nil {
				return false, fmt.Errorf("unable to receive syn token: %s", err)
			}
			claims, err := p.tokenaccessor.ParsePacketToken(&conn.Auth, msg)
			if err != nil || claims == nil {
				p.reportRejectedFlow(flowProperties, collector.DefaultEndPoint, puContext.ManagementID(), puContext, collector.InvalidToken, nil, nil)
				return isEncrypted, fmt.Errorf("reported rejected flow due to invalid token: %s", err)
			}
			tags := claims.T.Copy()
			tags.AppendKeyValue(enforcerconstants.PortNumberLabelString, strconv.Itoa(int(backendport)))
			report, packet := puContext.SearchRcvRules(tags)
			if packet.Action.Rejected() {
				p.reportRejectedFlow(flowProperties, conn.Auth.RemoteContextID, puContext.ManagementID(), puContext, collector.PolicyDrop, report, packet)
				return isEncrypted, fmt.Errorf("connection dropped by policy %s: ", packet.PolicyID)
			}

			if packet.Action.Encrypted() {
				isEncrypted = true
			}

			conn.ReportFlowPolicy = report
			conn.PacketFlowPolicy = packet
			conn.SetState(connection.ServerSendToken)

		case connection.ServerSendToken:
			if err := upConn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return false, err
			}
			claims, err := p.tokenaccessor.CreateSynAckPacketToken(puContext, &conn.Auth)
			if err != nil {
				return isEncrypted, fmt.Errorf("unable to create synack token: %s", err)
			}
			if n, err := writeMsg(upConn, claims); err != nil || n < len(claims) {
				zap.L().Error("Failed to write", zap.Error(err))
				return false, fmt.Errorf("Failed to write ack: %s", err)
			}
			conn.SetState(connection.ServerAuthenticatePair)

		case connection.ServerAuthenticatePair:
			if err := upConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return false, err
			}
			msg, err := readMsg(upConn)
			if err != nil {
				return false, fmt.Errorf("unable to receive ack token: %s", err)
			}
			if _, err := p.tokenaccessor.ParseAckToken(&conn.Auth, msg); err != nil {
				p.reportRejectedFlow(flowProperties, collector.DefaultEndPoint, puContext.ManagementID(), puContext, collector.InvalidFormat, nil, nil)
				return isEncrypted, fmt.Errorf("ack packet dropped because signature validation failed %s", err)
			}
			p.reportAcceptedFlow(flowProperties, conn.Auth.RemoteContextID, puContext.ManagementID(), puContext, conn.ReportFlowPolicy, conn.PacketFlowPolicy)
			return isEncrypted, nil
		}
	}
}

func (p *Proxy) reportFlow(flowproperties *proxyFlowProperties, sourceID string, destID string, context *pucontext.PUContext, mode string, reportAction *policy.FlowPolicy, packetAction *policy.FlowPolicy) {
	c := &collector.FlowRecord{
		ContextID: context.ID(),
		Source: &collector.EndPoint{
			ID:   sourceID,
			IP:   flowproperties.SourceIP,
			Port: flowproperties.SourcePort,
			Type: flowproperties.SourceType,
		},
		Destination: &collector.EndPoint{
			ID:   destID,
			IP:   flowproperties.DestIP,
			Port: flowproperties.DestPort,
			Type: flowproperties.DestType,
		},
		Tags:        context.Annotations(),
		Action:      packetAction.Action,
		DropReason:  mode,
		PolicyID:    reportAction.PolicyID,
		L4Protocol:  packet.IPProtocolTCP,
		ServiceType: policy.ServiceTCP,
		ServiceID:   flowproperties.ServiceID,
	}

	if reportAction.ObserveAction.Observed() {
		c.ObservedAction = packetAction.Action
		c.ObservedPolicyID = packetAction.PolicyID
	}

	p.collector.CollectFlowEvent(c)
}

func (p *Proxy) reportAcceptedFlow(flowproperties *proxyFlowProperties, sourceID string, destID string, context *pucontext.PUContext, report *policy.FlowPolicy, packet *policy.FlowPolicy) {

	p.reportFlow(flowproperties, sourceID, destID, context, "N/A", report, packet)
}

func (p *Proxy) reportRejectedFlow(flowproperties *proxyFlowProperties, sourceID string, destID string, context *pucontext.PUContext, mode string, report *policy.FlowPolicy, packet *policy.FlowPolicy) {

	if report == nil {
		report = &policy.FlowPolicy{
			Action:   policy.Reject,
			PolicyID: "default",
		}
	}
	if packet == nil {
		packet = report
	}
	p.reportFlow(flowproperties, sourceID, destID, context, mode, report, packet)
}

func readMsg(reader io.Reader) ([]byte, error) {

	lread := io.LimitReader(reader, 2)
	lbuf := make([]byte, 2)
	if _, err := lread.Read(lbuf); err != nil {
		return nil, fmt.Errorf("Invalid length: %s", err)
	}

	dataLength := binary.BigEndian.Uint16(lbuf)

	dread := io.LimitReader(reader, int64(dataLength))
	data := make([]byte, dataLength)
	if _, err := dread.Read(data); err != nil {
		return nil, fmt.Errorf("Not enough data to read: %s", err)
	}

	return data, nil
}

func writeMsg(conn io.Writer, data []byte) (n int, err error) {
	lbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lbuf, uint16(len(data)))
	data = append(lbuf, data...)
	return conn.Write(data)
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

func getIP(conn net.Conn) string {
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return addr.IP.String()
	}
	return ""
}
