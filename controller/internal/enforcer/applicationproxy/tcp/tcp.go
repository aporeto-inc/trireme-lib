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

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/applicationproxy/connproc"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/constants"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/connection"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/packet"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/pucontext"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/secrets"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
)

const (
	proxyMarkInt = 0x40 //Duplicated from supervisor/iptablesctrl refer to it
)

// Proxy maintains state for proxies connections from listen to backend.
type Proxy struct {
	wg sync.WaitGroup

	tokenaccessor tokenaccessor.TokenAccessor
	collector     collector.EventCollector

	puContext string
	puFromID  cache.DataStore

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
		wg:            sync.WaitGroup{},
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

// handle handles a connection
func (p *Proxy) handle(ctx context.Context, upConn net.Conn) {

	defer upConn.Close() // nolint

	ip, port, err := connproc.GetOriginalDestination(upConn)
	if err != nil {
		return
	}

	downConn, err := p.downConnection(ip, port)
	if err != nil {
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

	tlsConn := tls.Server(serverConn, &tls.Config{
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
}

func dataprocessor(ctx context.Context, source, dest net.Conn) {
	defer func() {
		switch dest.(type) {
		case *tls.Conn:
			dest.(*tls.Conn).CloseWrite() // nolint errcheck
		case *net.TCPConn:
			dest.(*net.TCPConn).CloseWrite() // nolint errcheck
		}
	}()
	b := make([]byte, 16384)
	for {
		// Setting a read deadline here. TODO: We need to account for keep-alives.
		if err := source.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
			n, err := source.Read(b)
			if err != nil {
				if checkErr(err) {
					continue
				}
			}
			if _, err = dest.Write(b[:n]); err != nil {
				if checkErr(err) {
					continue
				}
				return
			}
		}
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
func (p *Proxy) CompleteEndPointAuthorization(downIP fmt.Stringer, downPort int, upConn, downConn net.Conn) (bool, error) {

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
func (p *Proxy) StartClientAuthStateMachine(downIP fmt.Stringer, downPort int, downConn net.Conn) (bool, error) {

	// We are running on top of TCP nothing should be lost or come out of order makes the state machines easy....
	puContext, err := p.puContextFromContextID(p.puContext)
	if err != nil {
		return false, fmt.Errorf("Cannot find policy context: %s", err)
	}
	isEncrypted := false
	conn := connection.NewProxyConnection()

	flowproperties := &proxyFlowProperties{
		DestIP: downIP.String(),
		// SourceIP: downConn.LocalAddr().Network(),
	}

	// reader := bufio.NewReader(downConn)

	for {
		if err := downConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return false, err
		}
		switch conn.GetState() {
		case connection.ClientTokenSend:

			token, err := p.tokenaccessor.CreateSynPacketToken(puContext, &conn.Auth)
			if err != nil {
				return isEncrypted, fmt.Errorf("unable to create syn token: %s", err)
			}

			if n, err := writeMsg(downConn, token); err != nil || n < len(token) {
				return isEncrypted, fmt.Errorf("unable to send auth token: %s", err)
			}

			conn.SetState(connection.ClientPeerTokenReceive)

		case connection.ClientPeerTokenReceive:
			msg, err := readMsg(downConn)
			if err != nil {
				return false, fmt.Errorf("Failed to read peer token: %s", err)
			}

			claims, err := p.tokenaccessor.ParsePacketToken(&conn.Auth, msg)
			if err != nil || claims == nil {
				p.reportRejectedFlow(flowproperties, conn, collector.DefaultEndPoint, puContext.ManagementID(), puContext, collector.InvalidToken, nil, nil)
				return false, fmt.Errorf("peer token reject because of bad claims: error: %s, claims: %v %v", err, claims, string(msg))
			}

			report, packet := puContext.SearchTxtRules(claims.T, false)
			if packet.Action.Rejected() {
				p.reportRejectedFlow(flowproperties, conn, puContext.ManagementID(), conn.Auth.RemoteContextID, puContext, collector.PolicyDrop, report, packet)
				return isEncrypted, errors.New("dropping because of reject rule on transmitter")
			}

			if packet.Action.Encrypted() {
				isEncrypted = true
			}

			conn.SetState(connection.ClientSendSignedPair)

		case connection.ClientSendSignedPair:
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
		DestIP:   ip.String(),
		DestPort: uint16(backendport),
	}

	conn := connection.NewProxyConnection()
	conn.SetState(connection.ServerReceivePeerToken)

	for {
		if err := upConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return false, err
		}

		switch conn.GetState() {
		case connection.ServerReceivePeerToken:

			msg, err := readMsg(upConn)
			if err != nil {
				return false, fmt.Errorf("unable to receive syn token: %s", err)
			}

			claims, err := p.tokenaccessor.ParsePacketToken(&conn.Auth, msg)
			if err != nil || claims == nil {
				p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.ManagementID(), puContext, collector.InvalidToken, nil, nil)
				return isEncrypted, fmt.Errorf("reported rejected flow due to invalid token: %s", err)
			}

			claims.T = append(claims.T, enforcerconstants.PortNumberLabelString+"="+strconv.Itoa(int(backendport)))
			report, packet := puContext.SearchRcvRules(claims.T)
			if packet.Action.Rejected() {
				p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.ManagementID(), puContext, collector.PolicyDrop, report, packet)
				return isEncrypted, fmt.Errorf("connection dropped by policy %s: ", packet.PolicyID)
			}

			if packet.Action.Encrypted() {
				isEncrypted = true
			}

			conn.ReportFlowPolicy = report
			conn.PacketFlowPolicy = packet

			conn.SetState(connection.ServerSendToken)

		case connection.ServerSendToken:

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
			msg, err := readMsg(upConn)
			if err != nil {
				return false, fmt.Errorf("unable to receive ack token: %s", err)
			}

			if _, err := p.tokenaccessor.ParseAckToken(&conn.Auth, msg); err != nil {
				p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.ManagementID(), puContext, collector.InvalidFormat, nil, nil)
				return isEncrypted, fmt.Errorf("ack packet dropped because signature validation failed %s", err)
			}
			p.reportAcceptedFlow(flowProperties, conn, conn.Auth.RemoteContextID, puContext.ManagementID(), puContext, conn.ReportFlowPolicy, conn.PacketFlowPolicy)
			return isEncrypted, nil
		}
	}
}

func (p *Proxy) reportFlow(flowproperties *proxyFlowProperties, conn *connection.ProxyConnection, sourceID string, destID string, context *pucontext.PUContext, mode string, reportAction *policy.FlowPolicy, packetAction *policy.FlowPolicy) {
	c := &collector.FlowRecord{
		ContextID: context.ID(),
		Source: &collector.EndPoint{
			ID:   sourceID,
			IP:   flowproperties.SourceIP,
			Port: flowproperties.SourcePort,
			Type: collector.PU,
		},
		Destination: &collector.EndPoint{
			ID:   destID,
			IP:   flowproperties.DestIP,
			Port: flowproperties.DestPort,
			Type: collector.PU,
		},
		Tags:       context.Annotations(),
		Action:     reportAction.Action,
		DropReason: mode,
		PolicyID:   reportAction.PolicyID,
		L4Protocol: packet.IPProtocolTCP,
	}

	if reportAction.ObserveAction.Observed() {
		c.ObservedAction = packetAction.Action
		c.ObservedPolicyID = packetAction.PolicyID
	}

	p.collector.CollectFlowEvent(c)
}

func (p *Proxy) reportAcceptedFlow(flowproperties *proxyFlowProperties, conn *connection.ProxyConnection, sourceID string, destID string, context *pucontext.PUContext, report *policy.FlowPolicy, packet *policy.FlowPolicy) {

	p.reportFlow(flowproperties, conn, sourceID, destID, context, "N/A", report, packet)
}

func (p *Proxy) reportRejectedFlow(flowproperties *proxyFlowProperties, conn *connection.ProxyConnection, sourceID string, destID string, context *pucontext.PUContext, mode string, report *policy.FlowPolicy, packet *policy.FlowPolicy) {

	if report == nil {
		report = &policy.FlowPolicy{
			Action:   policy.Reject,
			PolicyID: "",
		}
	}
	if packet == nil {
		packet = report
	}
	p.reportFlow(flowproperties, conn, sourceID, destID, context, mode, report, packet)
}

func readMsg(reader io.Reader) ([]byte, error) {

	lread := io.LimitReader(reader, 2)
	lbuf := make([]byte, 2)
	if _, err := lread.Read(lbuf); err != nil && err != io.EOF {
		return nil, fmt.Errorf("Invalid length: %s", err)
	}

	dataLength := binary.BigEndian.Uint16(lbuf)

	dread := io.LimitReader(reader, int64(dataLength))
	data := make([]byte, dataLength)
	if _, err := dread.Read(data); err != nil && err != io.EOF {
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

func checkErr(err error) bool {
	if err == io.EOF {
		return false
	}
	switch t := err.(type) {
	case net.Error:
		if t.Timeout() {
			return true
		}
	case syscall.Errno:
		if t == syscall.ECONNRESET || t == syscall.ECONNABORTED || t == syscall.ENOTCONN || t == syscall.EPIPE {
			return false
		}
		zap.L().Error("Connection error to destination", zap.Error(err))
	default:
		zap.L().Error("Connection terminated", zap.Error(err))
	}
	return false
}
