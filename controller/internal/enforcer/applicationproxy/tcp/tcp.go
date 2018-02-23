// +build linux

package tcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/applicationproxy/connproc"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/constants"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/connection"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/pucontext"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
)

const (
	sockOptOriginalDst = 80
	proxyMarkInt       = 0x40 //Duplicated from supervisor/iptablesctrl refer to it

)

type secretsPEM interface {
	AuthPEM() []byte
	TransmittedPEM() []byte
	EncodingPEM() []byte
}

// Proxy maintains state for proxies connections from listen to backend.
type Proxy struct {
	wg sync.WaitGroup

	tokenaccessor tokenaccessor.TokenAccessor
	collector     collector.EventCollector

	puContext         string
	puFromID          cache.DataStore
	exposedServices   cache.DataStore
	dependentServices cache.DataStore

	certificate *tls.Certificate
	ca          *x509.CertPool

	// List of local IP's
	localIPs map[string]struct{}

	sync.Mutex
}

// proxyFlowProperties is a struct used to pass flow information up
type proxyFlowProperties struct {
	SourceIP   net.IP
	DestIP     net.IP
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
	exposedServices cache.DataStore,
	dependentServices cache.DataStore,
) *Proxy {

	localIPs := connproc.GetInterfaces()

	return &Proxy{
		wg:                sync.WaitGroup{},
		collector:         c,
		tokenaccessor:     tp,
		puFromID:          puFromID,
		puContext:         puContext,
		localIPs:          localIPs,
		certificate:       certificate,
		exposedServices:   exposedServices,
		dependentServices: dependentServices,
		ca:                caPool,
	}
}

// RunNetworkServer implements enforcer.Enforcer interface
func (p *Proxy) RunNetworkServer(ctx context.Context, listener net.Listener, encrypted bool) error {

	// Encryption is done transparently for TCP.
	go p.serve(ctx, listener)

	return nil
}

// UpdateSecrets updates the secrets of the connections.
func (p *Proxy) UpdateSecrets(cert *tls.Certificate, caPool *x509.CertPool) {
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
				filehdl, err := conn.(*net.TCPConn).File()
				if err != nil {
					zap.L().Error("Cannot open file handle for connection", zap.Error(err))
				}

				if err = syscall.SetsockoptInt(int(filehdl.Fd()), syscall.SOL_SOCKET, syscall.SO_MARK, proxyMarkInt); err != nil {
					zap.L().Error("Cannot set mark for connection:", zap.Error(err))
				}

				go func() {
					p.handle(ctx, conn)
					if connErr := conn.Close(); connErr != nil {
						zap.L().Error("Failed to close DownConn", zap.String("PU ID", p.puContext))
					}
				}()
			} else {
				return
			}
		}
	}
}

func (p *Proxy) ShutDown() error {
	return nil
}

// handle handles a connection
func (p *Proxy) handle(ctx context.Context, upConn net.Conn) {

	ip, port, err := connproc.GetOriginalDestination(upConn)
	if err != nil {
		return
	}

	downConn, err := p.downConnection(ip, port)
	if err != nil {
		if downConn > 0 {
			if err = syscall.Close(downConn); err != nil {
				zap.L().Error("Cannot close DownConn", zap.String("ContextID", p.puContext), zap.Error(err))
			}
		}
		return
	}

	defer func() {
		if err = syscall.Close(downConn); err != nil {
			zap.L().Error("Unable to close DownConn", zap.Error(err))
		}
	}()

	var isEncrypted bool
	// Now let us handle the state machine for the down connection
	if isEncrypted, err = p.CompleteEndPointAuthorization(string(ip), port, upConn, downConn); err != nil {
		zap.L().Error("Error on Authorization", zap.Error(err))
		return
	}

	if isEncrypted {
		if err := p.handleEncryptedData(ctx, upConn, downConn, ip); err != nil {
			zap.L().Error("Failed to process connection - aborting", zap.Error(err))
		}
	}

	if err := Pipe(ctx, upConn.(*net.TCPConn), downConn); err != nil {
		zap.L().Error("Failed to handle data pipe - aborting", zap.Error(err))
	}
}

func (p *Proxy) startEncryptedClientDataPath(ctx context.Context, fd int, conn io.ReadWriter) error {
	tlsFs := os.NewFile(uintptr(fd), "TLSSOCK")
	if tlsFs == nil {
		return fmt.Errorf("Cannot convert to Fs")
	}
	netConn, _ := net.FileConn(tlsFs)
	tlsConn := tls.Client(netConn, &tls.Config{
		ClientCAs: p.ca,
	})

	if tlsConn == nil {
		return fmt.Errorf("Cannot convert to tls Connection")
	}
	if err := tlsConn.Handshake(); err != nil {
		return err
	}

	p.copyData(ctx, netConn, tlsConn)
	return nil
}

func (p *Proxy) startEncryptedServerDataPath(ctx context.Context, fd int, conn net.Conn) error {

	p.Lock()
	certs := []tls.Certificate{*p.certificate}
	p.Unlock()

	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: certs,
	})
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		return err
	}

	fs := os.NewFile(uintptr(fd), "NONTLSSOCK")
	netConn, _ := net.FileConn(fs)

	p.copyData(ctx, netConn, tlsConn)
	return nil
}

func (p *Proxy) copyData(ctx context.Context, netConn net.Conn, tlsConn *tls.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		b := make([]byte, 1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if n, err := tlsConn.Read(b); err == nil {
					if _, err = netConn.Write(b[:n]); err != nil {
						return
					}
					continue
				}
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		b := make([]byte, 1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if n, err := netConn.Read(b); err == nil {
					if _, err = tlsConn.Write(b[:n]); err != nil {
						return
					}
					continue
				}
				return
			}
		}
	}()
	wg.Wait()
}

func (p *Proxy) handleEncryptedData(ctx context.Context, upConn net.Conn, downConn int, ip net.IP) error {
	// If the destination is not a local IP, it means that we are processing a client connection.
	if _, ok := p.localIPs[ip.String()]; !ok {
		return p.startEncryptedClientDataPath(ctx, downConn, upConn)
	}
	return p.startEncryptedServerDataPath(ctx, downConn, upConn)
}

func getsockopt(s int, level int, name int, val uintptr, vallen *uint32) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e1 != 0 {
		err = e1
	}
	return
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
func (p *Proxy) downConnection(ip net.IP, port int) (int, error) {

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		zap.L().Error("Socket create failed", zap.String("Error", err.Error()))
	}

	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, proxyMarkInt)
	if err != nil {
		zap.L().Error("Sockopt  failed", zap.String("Error", err.Error()))
	}

	address := &syscall.SockaddrInet4{
		Port: port,
	}
	copy(address.Addr[:], ip)

	err = syscall.Connect(fd, address)
	if err != nil {
		zap.L().Error("Connect Error", zap.String("Connect Error", err.Error()))
		return fd, err
	}

	return fd, nil
}

// CompleteEndPointAuthorization -- Aporeto Handshake on top of a completed connection
// We will define states here equivalent to SYN_SENT AND SYN_RECEIVED
func (p *Proxy) CompleteEndPointAuthorization(backendip string, backendport int, upConn net.Conn, downConn int) (bool, error) {
	// If the backend is not a local IP it means that we are a client.
	if _, ok := p.localIPs[backendip]; !ok {
		return p.StartClientAuthStateMachine(backendip, backendport, upConn, downConn)
	}

	return p.StartServerAuthStateMachine(backendip, backendport, upConn, downConn)
}

//StartClientAuthStateMachine -- Starts the aporeto handshake for client application
func (p *Proxy) StartClientAuthStateMachine(backendip string, backendport int, upConn net.Conn, downConn int) (bool, error) {

	// We are running on top of TCP nothing should be lost or come out of order makes the state machines easy....
	puContext, err := p.puContextFromContextID(p.puContext)
	if err != nil {
		return false, err
	}
	isEncrypted := false
	conn := connection.NewProxyConnection()
	toAddr, _ := syscall.Getpeername(downConn)
	localaddr, _ := syscall.Getsockname(downConn)
	localinet4ip, _ := localaddr.(*syscall.SockaddrInet4)
	remoteinet4ip, _ := toAddr.(*syscall.SockaddrInet4)
	flowProperties := &proxyFlowProperties{
		SourceIP:   net.IPv4(localinet4ip.Addr[0], localinet4ip.Addr[1], localinet4ip.Addr[2], localinet4ip.Addr[3]),
		DestIP:     net.IPv4(remoteinet4ip.Addr[0], remoteinet4ip.Addr[1], remoteinet4ip.Addr[2], remoteinet4ip.Addr[3]),
		SourcePort: uint16(localinet4ip.Port),
		DestPort:   uint16(remoteinet4ip.Port),
	}

L:
	for conn.GetState() == connection.ClientTokenSend {
		msg := make([]byte, 1024)
		for {
			switch conn.GetState() {

			case connection.ClientTokenSend:

				if p.tokenaccessor == nil {
					return isEncrypted, fmt.Errorf("NIL TOKENAccessor")
				}
				token, err := p.tokenaccessor.CreateSynPacketToken(puContext, &conn.Auth)
				if err != nil {
					return isEncrypted, fmt.Errorf("unable to create syn token: %s", err)
				}

				zap.L().Error("Sending token", zap.String("Token", hex.Dump(token)))
				if err := syscall.Sendto(downConn, token, 0, toAddr); err != nil {
					return isEncrypted, fmt.Errorf("unable to send syn: %s", err)
				}
				conn.SetState(connection.ClientPeerTokenReceive)

			case connection.ClientPeerTokenReceive:
				n, _, err := syscall.Recvfrom(downConn, msg, 0)
				if err != nil {
					return isEncrypted, fmt.Errorf("unable to recvfrom: %s", err)
				}

				msg = msg[:n]
				claims, err := p.tokenaccessor.ParsePacketToken(&conn.Auth, msg)
				if err != nil || claims == nil {
					p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.ManagementID(), puContext, collector.InvalidToken, nil, nil)
					return false, fmt.Errorf("peer token reject because of bad claims: error: %s, claims: %v", err, claims)
				}

				report, packet := puContext.SearchTxtRules(claims.T, false)
				if packet.Action.Rejected() {
					p.reportRejectedFlow(flowProperties, conn, puContext.ManagementID(), conn.Auth.RemoteContextID, puContext, collector.PolicyDrop, report, packet)
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
				if err := syscall.Sendto(downConn, token, 0, toAddr); err != nil {
					return isEncrypted, fmt.Errorf("unable to send ack: %s", err)
				}
				break L
			}

		}
	}
	return isEncrypted, nil

}

// StartServerAuthStateMachine -- Start the aporeto handshake for a server application
func (p *Proxy) StartServerAuthStateMachine(backendip string, backendport int, upConn io.ReadWriter, downConn int) (bool, error) {

	puID, err := p.exposedServices.Get(backendport)
	if err != nil {
		return false, fmt.Errorf("Failed to find context for this service")
	}

	puContext, err := p.puContextFromContextID(puID.(string))
	if err != nil {
		return false, err
	}
	isEncrypted := false
	toAddr, _ := syscall.Getpeername(downConn)
	localaddr, _ := syscall.Getsockname(downConn)
	localinet4ip, _ := localaddr.(*syscall.SockaddrInet4)
	remoteinet4ip, _ := toAddr.(*syscall.SockaddrInet4)
	flowProperties := &proxyFlowProperties{
		SourceIP:   net.IPv4(localinet4ip.Addr[0], localinet4ip.Addr[1], localinet4ip.Addr[2], localinet4ip.Addr[3]),
		DestIP:     net.IPv4(remoteinet4ip.Addr[0], remoteinet4ip.Addr[1], remoteinet4ip.Addr[2], remoteinet4ip.Addr[3]),
		SourcePort: uint16(localinet4ip.Port),
		DestPort:   uint16(remoteinet4ip.Port),
	}
	conn := connection.NewProxyConnection()
	conn.SetState(connection.ServerReceivePeerToken)

E:
	for conn.GetState() == connection.ServerReceivePeerToken {
		for {
			msg := []byte{}

			switch conn.GetState() {
			case connection.ServerReceivePeerToken:
				for {
					data := make([]byte, 1024)
					n, err := upConn.Read(data)
					if n < 1024 || err == nil {
						msg = append(msg, data[:n]...)
						break
					}
					if err != nil {
						return isEncrypted, err
					}
					msg = append(msg, data[:n]...)
				}

				claims, err := p.tokenaccessor.ParsePacketToken(&conn.Auth, msg)
				if err != nil || claims == nil {
					p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.ManagementID(), puContext, collector.InvalidToken, nil, nil)
					return isEncrypted, fmt.Errorf("reported rejected flow due to invalid token: %s", err)
				}

				claims.T.AppendKeyValue(enforcerconstants.PortNumberLabelString, strconv.Itoa(int(backendport)))
				report, packet := puContext.SearchRcvRules(claims.T)
				if packet.Action.Rejected() {
					p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.ManagementID(), puContext, collector.PolicyDrop, report, packet)
					return isEncrypted, fmt.Errorf("connection dropped by policy %s: %s", packet.PolicyID, err)
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
				synackn, err := upConn.Write(claims)
				if err != nil {
					zap.L().Error("Failed to write", zap.Error(err))
				}
				zap.L().Debug("Returned SynACK Token size", zap.Int("Token Length", synackn))
				conn.SetState(connection.ServerAuthenticatePair)

			case connection.ServerAuthenticatePair:
				for {
					data := make([]byte, 1024)
					n, err := upConn.Read(data)
					if n < 1024 || err == nil {
						msg = append(msg, data[:n]...)
						break
					}
					if err != nil {
						return isEncrypted, err
					}
					msg = append(msg, data[:n]...)
				}
				if _, err := p.tokenaccessor.ParseAckToken(&conn.Auth, msg); err != nil {
					p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.ManagementID(), puContext, collector.InvalidFormat, nil, nil)
					return isEncrypted, fmt.Errorf("ack packet dropped because signature validation failed %s", err)
				}

				break E
			}
		}
	}

	p.reportAcceptedFlow(flowProperties, conn, conn.Auth.RemoteContextID, puContext.ManagementID(), puContext, conn.ReportFlowPolicy, conn.PacketFlowPolicy)
	return isEncrypted, nil
}

func (p *Proxy) reportFlow(flowproperties *proxyFlowProperties, conn *connection.ProxyConnection, sourceID string, destID string, context *pucontext.PUContext, mode string, report *policy.FlowPolicy, packet *policy.FlowPolicy) {
	c := &collector.FlowRecord{
		ContextID: context.ID(),
		Source: &collector.EndPoint{
			ID:   sourceID,
			IP:   flowproperties.SourceIP.String(),
			Port: flowproperties.SourcePort,
			Type: collector.PU,
		},
		Destination: &collector.EndPoint{
			ID:   destID,
			IP:   flowproperties.DestIP.String(),
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
