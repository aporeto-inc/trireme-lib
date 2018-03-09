package tcp

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/applicationproxy/connproc"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/constants"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/connection"
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

	sync.Mutex
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
			if conn, err := listener.Accept(); err == nil {
				if err := markedconn.MarkConnection(conn, proxyMarkInt); err != nil {
					zap.L().Error("Failed to mark connection", zap.Error(err))
				}

				go p.handle(ctx, conn)
			} else {
				return
			}
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

	// Before we start the process, listen to context signals and cancel
	// everything
	// TODO: Fix this ...
	go func() {
		select {
		case <-ctx.Done():
			upConn.Close()   // nolint
			downConn.Close() // nolint
		}
	}()

	var isEncrypted bool
	// Now let us handle the state machine for the down connection
	if isEncrypted, err = p.CompleteEndPointAuthorization(ip, port, upConn, downConn); err != nil {
		zap.L().Error("Error on Authorization", zap.Error(err))
		return
	}

	if isEncrypted {
		if err := p.handleEncryptedData(ctx, upConn, downConn, ip); err != nil {
			zap.L().Error("Failed to process connection - aborting", zap.Error(err))
		}
		fmt.Println("Done with the connection")
		return
	}

	if err := connproc.Pipe(ctx, upConn, downConn); err != nil {
		zap.L().Error("Failed to handle data pipe - aborting", zap.Error(err))
	}
}

func (p *Proxy) startEncryptedClientDataPath(ctx context.Context, downConn net.Conn, serverConn net.Conn, ip net.IP) error {

	p.Lock()
	ca := p.ca
	p.Unlock()

	tlsConn := tls.Client(downConn, &tls.Config{
		InsecureSkipVerify: true,
		ClientCAs:          ca,
	})

	// VERY BAD HACK ... Handshake locks because the write is not complete
	/// for testing purposes only
	time.Sleep(10 * time.Microsecond)

	if err := tlsConn.Handshake(); err != nil {
		return err
	}

	p.copyData(ctx, serverConn, tlsConn, true)
	fmt.Println("Done client")
	return nil
}

func (p *Proxy) startEncryptedServerDataPath(ctx context.Context, downConn net.Conn, serverConn net.Conn) error {

	p.Lock()
	certs := []tls.Certificate{*p.certificate}
	p.Unlock()

	tlsConn := tls.Server(serverConn, &tls.Config{
		Certificates: certs,
	})
	defer tlsConn.Close() // nolint

	if err := tlsConn.Handshake(); err != nil {
		return err
	}

	p.copyData(ctx, tlsConn, downConn, false)
	fmt.Println("Done server")
	return nil
}

func (p *Proxy) copyData(ctx context.Context, source, dest net.Conn, tlsDest bool) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer func() {
			if tlsDest {
				dest.(*tls.Conn).CloseWrite()
			} else {
				dest.(*net.TCPConn).CloseWrite()
			}
			wg.Done()
		}()
		b := make([]byte, 1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, err := source.Read(b)
				if err != nil {
					return
				}
				if _, err = dest.Write(b[:n]); err != nil {
					return
				}
			}
		}
	}()

	go func() {
		defer func() {
			wg.Done()
		}()
		b := make([]byte, 1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, err := dest.Read(b)
				if err != nil {
					return
				}
				if _, err = source.Write(b[:n]); err != nil {
					return
				}
				return
			}
		}
	}()
	wg.Wait()
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

	isEncrypted, reader, err := p.StartServerAuthStateMachine(downIP, downPort, upConn)
	if err != nil {
		return false, err
	}

	if length := reader.Buffered(); !isEncrypted && length > 0 {
		if err := flushBuffer(reader, downConn, length); err != nil {
			return false, err
		}
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

	reader := bufio.NewReader(downConn)

	for {
		if err := downConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
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
			msg, err := readMsg(reader)
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
func (p *Proxy) StartServerAuthStateMachine(ip fmt.Stringer, backendport int, upConn net.Conn) (bool, *bufio.Reader, error) {

	puContext, err := p.puContextFromContextID(p.puContext)
	if err != nil {
		return false, nil, err
	}
	isEncrypted := false

	flowProperties := &proxyFlowProperties{
		DestIP:   ip.String(),
		DestPort: uint16(backendport),
	}

	conn := connection.NewProxyConnection()
	conn.SetState(connection.ServerReceivePeerToken)

	reader := bufio.NewReader(upConn)

	for {
		if err := upConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return false, nil, err
		}

		switch conn.GetState() {
		case connection.ServerReceivePeerToken:

			msg, err := readMsg(reader)
			if err != nil {
				return false, nil, fmt.Errorf("unable to receive syn token: %s", err)
			}

			claims, err := p.tokenaccessor.ParsePacketToken(&conn.Auth, msg)
			if err != nil || claims == nil {
				p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.ManagementID(), puContext, collector.InvalidToken, nil, nil)
				return isEncrypted, nil, fmt.Errorf("reported rejected flow due to invalid token: %s", err)
			}

			claims.T.AppendKeyValue(enforcerconstants.PortNumberLabelString, strconv.Itoa(int(backendport)))
			report, packet := puContext.SearchRcvRules(claims.T)
			if packet.Action.Rejected() {
				p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.ManagementID(), puContext, collector.PolicyDrop, report, packet)
				return isEncrypted, nil, fmt.Errorf("connection dropped by policy %s: %s", packet.PolicyID, err)
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
				return isEncrypted, nil, fmt.Errorf("unable to create synack token: %s", err)
			}

			if n, err := writeMsg(upConn, claims); err != nil || n < len(claims) {
				zap.L().Error("Failed to write", zap.Error(err))
				return false, nil, fmt.Errorf("Failed to write ack: %s", err)
			}

			conn.SetState(connection.ServerAuthenticatePair)

		case connection.ServerAuthenticatePair:
			msg, err := readMsg(reader)
			if err != nil {
				return false, nil, fmt.Errorf("unable to receive ack token: %s", err)
			}

			if _, err := p.tokenaccessor.ParseAckToken(&conn.Auth, msg); err != nil {
				p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.ManagementID(), puContext, collector.InvalidFormat, nil, nil)
				return isEncrypted, nil, fmt.Errorf("ack packet dropped because signature validation failed %s", err)
			}
			p.reportAcceptedFlow(flowProperties, conn, conn.Auth.RemoteContextID, puContext.ManagementID(), puContext, conn.ReportFlowPolicy, conn.PacketFlowPolicy)
			return isEncrypted, reader, nil
		}
	}
}

func (p *Proxy) reportFlow(flowproperties *proxyFlowProperties, conn *connection.ProxyConnection, sourceID string, destID string, context *pucontext.PUContext, mode string, report *policy.FlowPolicy, packet *policy.FlowPolicy) {
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
		Action:     report.Action,
		DropReason: mode,
		PolicyID:   report.PolicyID,
	}

	if report.ObserveAction.Observed() {
		c.ObservedAction = packet.Action
		c.ObservedPolicyID = packet.PolicyID
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

func readMsg(reader *bufio.Reader) ([]byte, error) {
	msg := []byte{}
	for i := 0; i < 20; {
		data, err := reader.ReadBytes('\n')
		if err != nil {
			return []byte{}, fmt.Errorf("unable to recv reply token: %s", err)
		}
		msg = append(msg, data...)
		i = i + len(data)
	}

	return msg[:len(msg)-1], nil
}

func writeMsg(conn io.Writer, data []byte) (n int, err error) {

	data = append(data, '\n')
	n, err = conn.Write(data)
	return n - 1, err
}

func flushBuffer(reader io.Reader, downConn io.Writer, length int) error {
	data := make([]byte, length)
	for n := 0; n < length; {
		l, err := reader.Read(data)
		if err != nil {
			return err
		}
		n = n + l
		if _, err := downConn.Write(data); err != nil {
			return err
		}
	}
	return nil
}
