// +build linux

package tcp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"go.uber.org/zap"

	"github.com/aporeto-inc/netlink-go/conntrack"
	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/connection"
	"github.com/aporeto-inc/trireme-lib/enforcer/constants"
	"github.com/aporeto-inc/trireme-lib/enforcer/datapath/tokenaccessor"
	"github.com/aporeto-inc/trireme-lib/enforcer/policyenforcer"
	"github.com/aporeto-inc/trireme-lib/enforcer/pucontext"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/internal/portset"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
)

const (
	sockOptOriginalDst = 80
	proxyMarkInt       = 0x40 //Duplicated from supervisor/iptablesctrl refer to it

)

// Proxy maintains state for proxies connections from listen to backend.
type Proxy struct {
	// Listen specifies port to listen on.
	Listen string
	// Backend address of the backend
	Backend string
	// certPath certificate path
	certPath string
	keyPath  string
	wg       sync.WaitGroup
	// Forward specifies if we should forward this connection.
	Forward bool
	// Encrypt specifies if this connection encrypted.
	Encrypt             bool
	mutualAuthorization bool
	tokenaccessor       tokenaccessor.TokenAccessor
	collector           collector.EventCollector
	puFromContextID     cache.DataStore
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
func NewProxy(listen string, forward bool, encrypt bool, tp tokenaccessor.TokenAccessor, c collector.EventCollector, puFromContextID cache.DataStore, mutualAuthorization bool) policyenforcer.Enforcer {
	ifaces, _ := net.Interfaces()
	iplist := []string{}
	for _, intf := range ifaces {
		addrs, _ := intf.Addrs()
		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ip.To4() != nil {
				iplist = append(iplist, ip.String())
			}
		}
	}

	return &Proxy{
		Forward:             forward,
		Encrypt:             encrypt,
		wg:                  sync.WaitGroup{},
		mutualAuthorization: mutualAuthorization,
		collector:           c,
		tokenaccessor:       tp,
		puFromContextID:     puFromContextID,
		socketListeners:     cache.NewCache("socketlisterner"),
		IPList:              iplist,
	}
}

// Enforce implements policyenforcer.Enforcer interface
func (p *Proxy) Enforce(contextID string, puInfo *policy.PUInfo) error {

	_, err := p.puFromContextID.Get(contextID)
	if err != nil {
		//Start proxy
		errChan := make(chan error, 1)

		port := puInfo.Runtime.Options().ProxyPort

		go p.StartListener(contextID, errChan, port)
		err, closed := <-errChan
		if closed {
			return nil
		}
		if err != nil {
			return err
		}
	}
	// Nothing required for the update case we will use the parent datapath structures to store state about PU
	return nil

}

// StartListener implements policyenforcer.Enforcer interface
func (p *Proxy) StartListener(contextID string, reterr chan error, port string) {

	var err error
	var listener net.Listener
	port = ":" + port
	if p.Forward || !p.Encrypt {
		if listener, err = net.Listen("tcp", port); err != nil {
			zap.L().Warn("Failed to Bind", zap.Error(err))
			reterr <- nil
			return

		}

	} else {
		config, err := p.loadTLS()
		if err != nil {
			reterr <- err
		}

		if listener, err = tls.Listen("tcp", port, config); err != nil {
			reterr <- err
		}
	}
	//At this point we are done initing lets close channel
	close(reterr)

	p.socketListeners.AddOrUpdate(contextID, &socketListenerEntry{
		listen: listener,
		port:   port,
	})
	for {

		if conn, err := listener.Accept(); err == nil {
			filehdl, _ := conn.(*net.TCPConn).File()
			err = syscall.SetsockoptInt(int(filehdl.Fd()), syscall.SOL_SOCKET, syscall.SO_MARK, proxyMarkInt)

			if err != nil {
				zap.L().Error(err.Error())
			}

			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				p.handle(conn, contextID)
				if connErr := conn.Close(); connErr != nil {
					zap.L().Error("Failed to close DownConn", zap.String("ContextID", contextID))
				}

			}()
		} else {
			return
		}

	}
}

// Unenforce implements policyenforcer.Enforcer interface
func (p *Proxy) Unenforce(contextID string) error {

	entry, err := p.socketListeners.Get(contextID)
	if err == nil {
		if cerr := entry.(*socketListenerEntry).listen.Close(); cerr != nil {
			zap.L().Error("Close failed for downconn", zap.String("ContextID", contextID))
		}
	}
	if err = p.socketListeners.Remove(contextID); err != nil {
		zap.L().Error("Cannot remove Socket Listener", zap.Error(err), zap.String("ContextID", contextID))
	}
	return nil
}

// GetFilterQueue is a stub for TCP proxy
func (p *Proxy) GetFilterQueue() *fqconfig.FilterQueue {
	return nil
}

// GetPortSetInstance returns nil for the proxy
func (p *Proxy) GetPortSetInstance() portset.PortSet {
	return nil
}

// Start is a stub for TCP proxy
func (p *Proxy) Start() error {
	return nil

}

// Stop stops and waits proxy to stop.
func (p *Proxy) Stop() error {
	p.wg.Wait()
	return nil
}

// UpdateSecrets updates the secrets of running enforcers managed by trireme. Remote enforcers will get the secret updates with the next policy push
func (p *Proxy) UpdateSecrets(secrets secrets.Secrets) error {
	return nil
}

// loadTLS configuration - static files for the time being
func (p *Proxy) loadTLS() (*tls.Config, error) {

	cert, err := tls.LoadX509KeyPair(p.certPath, p.keyPath)
	if err != nil {
		return nil, err
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}, nil
}

// handle handles a connection
func (p *Proxy) handle(upConn net.Conn, contextID string) {
	var err error

	var ip []byte
	var port uint16
	defer func() {
		if err = upConn.Close(); err != nil {
			zap.L().Error("Failed to close UpConn", zap.Error(err))
		}
	}()

	//backend := p.Backend
	if p.Forward {
		ip, port, err = getOriginalDestination(upConn)
		if err != nil {
			return
		}
	}

	downConn, err := p.downConnection(ip, port)
	if err != nil {
		if downConn > 0 {
			if err = syscall.Close(downConn); err != nil {
				zap.L().Error("Cannot close DownConn", zap.String("ContextID", contextID), zap.Error(err))
			}
		}
		return
	}

	defer func() {
		if err = syscall.Close(downConn); err != nil {
			zap.L().Error("Unable to close DownConn", zap.Error(err))
		}
	}()

	isEncrypted := false
	// Now let us handle the state machine for the down connection
	if isEncrypted, err = p.CompleteEndPointAuthorization(string(ip), port, upConn, downConn, contextID); err != nil {
		zap.L().Error("Error on Authorization", zap.Error(err))
		return
	}
	if !isEncrypted {
		if err := Pipe(upConn.(*net.TCPConn), downConn); err != nil {
			fmt.Printf("pipe failed: %s", err)
		}
	} else {
		// Hand off encryption to service processor for proxied traffic

	}
}

func getsockopt(s int, level int, name int, val uintptr, vallen *uint32) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

// getOriginalDestination -- Func to get original destination of redirected packet. Used to figure out backend destination
func getOriginalDestination(conn net.Conn) ([]byte, uint16, error) {
	var addr sockaddr
	size := uint32(unsafe.Sizeof(addr))

	inFile, err := conn.(*net.TCPConn).File()
	if err != nil {
		return []byte{}, 0, err
	}

	err = getsockopt(int(inFile.Fd()), syscall.SOL_IP, sockOptOriginalDst, uintptr(unsafe.Pointer(&addr)), &size)
	if err != nil {
		return []byte{}, 0, err
	}

	var ip net.IP
	if addr.family != syscall.AF_INET {
		return []byte{}, 0, errors.New("invalid address family")

	}

	ip = addr.data[2:6]
	port := uint16(int(addr.data[0])<<8 + int(addr.data[1]))

	return ip, port, nil
}

func (p *Proxy) puContextFromContextID(contextID string) (*pucontext.PUContext, error) {

	ctx, err := p.puFromContextID.Get(contextID)
	if err != nil {
		return nil, fmt.Errorf("Context not found %s", contextID)
	}

	puContext, ok := ctx.(*pucontext.PUContext)
	if !ok {
		return nil, fmt.Errorf("Context not converted %s", contextID)
	}

	return puContext, nil
}

// Initiate the downstream connection
func (p *Proxy) downConnection(ip []byte, port uint16) (int, error) {

	var err error
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		zap.L().Error("Socket create failed", zap.String("Error", err.Error()))
	}

	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, proxyMarkInt)
	if err != nil {
		zap.L().Error("Sockopt  failed", zap.String("Error", err.Error()))
	}
	address := &syscall.SockaddrInet4{
		Port: int(port),
	}
	copy(address.Addr[:], ip)
	if p.Encrypt && p.Forward {
		// config, err := p.loadTLS()
		// if err != nil {
		// 	return nil, err
		// }

		// downConn, err = tls.Dial("tcp", backend, config)
		// if err != nil {
		// 	return nil, err
		// }
	} else {
		err = syscall.Connect(fd, address)
		if err != nil {
			zap.L().Error("Connect Error", zap.String("Connect Error", err.Error()))
			return fd, err
		}
		addr, _ := syscall.Getpeername(fd)
		remote := addr.(*syscall.SockaddrInet4)
		addr, _ = syscall.Getsockname(fd)
		local := addr.(*syscall.SockaddrInet4)

		conntrackHdl := conntrack.NewHandle()

		if connterror := conntrackHdl.ConntrackTableUpdateMark(net.IPv4(local.Addr[0], local.Addr[1], local.Addr[2], local.Addr[3]).String(),
			net.IPv4(remote.Addr[0], remote.Addr[1], remote.Addr[2], remote.Addr[3]).String(),
			syscall.IPPROTO_TCP,
			uint16(local.Port),
			uint16(remote.Port),
			constants.DefaultConnMark,
		); connterror != nil {
			zap.L().Error("Unable to mark flow")
		}

	}

	return fd, nil
}

// CompleteEndPointAuthorization -- Aporeto Handshake on top of a completed connection
// We will define states here equivalent to SYN_SENT AND SYN_RECEIVED
func (p *Proxy) CompleteEndPointAuthorization(backendip string, backendport uint16, upConn net.Conn, downConn int, contextID string) (bool, error) {

	puContext, err := p.puContextFromContextID(contextID)
	if err != nil {
		return false, err
	}

	puContext.Lock()
	defer puContext.Unlock()

	if puContext.Type() == constants.LinuxProcessPU {
		//Are we client or server proxy

		if len(puContext.Ports()) > 0 && puContext.Ports()[0] != "0" {
			return p.StartServerAuthStateMachine(backendip, backendport, upConn, downConn, contextID)
		}
		//We are client no advertised port
		return p.StartClientAuthStateMachine(backendip, backendport, upConn, downConn, contextID)

	}
	//Assumption within a container two applications talking to each other won't be proxied.
	//If backend ip is non local we are client else we are server
	islocalIP := func() bool {
		for _, ip := range p.IPList {
			if ip == backendip {
				return true
			}
		}
		return false
	}()
	if islocalIP {
		return p.StartServerAuthStateMachine(backendip, backendport, upConn, downConn, contextID)
	}
	return p.StartClientAuthStateMachine(backendip, backendport, upConn, downConn, contextID)

}

//StartClientAuthStateMachine -- Starts the aporeto handshake for client application
func (p *Proxy) StartClientAuthStateMachine(backendip string, backendport uint16, upConn net.Conn, downConn int, contextID string) (bool, error) {

	// We are running on top of TCP nothing should be lost or come out of order makes the state machines easy....
	puContext, err := p.puContextFromContextID(contextID)
	if err != nil {
		return false, err
	}
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
				token, err := p.tokenaccessor.CreateSynPacketToken(puContext, &conn.Auth)
				if err != nil {
					return false, fmt.Errorf("unable to create syn token: %s", err)
				}
				if err := syscall.Sendto(downConn, token, 0, toAddr); err != nil {
					return false, fmt.Errorf("unable to send syn: %s", err)
				}
				conn.SetState(connection.ClientPeerTokenReceive)

			case connection.ClientPeerTokenReceive:
				n, _, err := syscall.Recvfrom(downConn, msg, 0)
				if err != nil {
					return false, fmt.Errorf("unable to recvfrom: %s", err)
				}

				msg = msg[:n]
				claims, err := p.tokenaccessor.ParsePacketToken(&conn.Auth, msg)
				if err != nil || claims == nil {
					p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.ManagementID(), puContext, collector.InvalidToken, nil, nil)
					return false, fmt.Errorf("peer token reject because of bad claims: error: %s, claims: %v", err, claims)
				}

				if p.mutualAuthorization {
					report, packet := puContext.SearchTxtRules(claims.T, !p.mutualAuthorization)
					if packet.Action.Rejected() {
						p.reportRejectedFlow(flowProperties, conn, puContext.ManagementID(), conn.Auth.RemoteContextID, puContext, collector.PolicyDrop, report, packet)
						return false, errors.New("dropping because of reject rule on transmitter")
					}
				}
				conn.SetState(connection.ClientSendSignedPair)

			case connection.ClientSendSignedPair:
				token, err := p.tokenaccessor.CreateAckPacketToken(puContext, &conn.Auth)
				if err != nil {
					return false, fmt.Errorf("unable to create ack token: %s", err)
				}
				if err := syscall.Sendto(downConn, token, 0, toAddr); err != nil {
					return false, fmt.Errorf("unable to send ack: %s", err)
				}
				break L
			}

		}
	}
	return false, nil

}

// StartServerAuthStateMachine -- Start the aporeto handshake for a server application
func (p *Proxy) StartServerAuthStateMachine(backendip string, backendport uint16, upConn io.ReadWriter, downConn int, contextID string) (bool, error) {

	puContext, err := p.puContextFromContextID(contextID)
	if err != nil {
		return false, err
	}
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
						return false, err
					}
					msg = append(msg, data[:n]...)
				}

				claims, err := p.tokenaccessor.ParsePacketToken(&conn.Auth, msg)
				if err != nil || claims == nil {
					p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.ManagementID(), puContext, collector.InvalidToken, nil, nil)
					return false, fmt.Errorf("reported rejected flow due to invalid token: %s", err)
				}

				claims.T.AppendKeyValue(enforcerconstants.PortNumberLabelString, strconv.Itoa(int(backendport)))
				report, packet := puContext.SearchRcvRules(claims.T)
				if packet.Action.Rejected() {
					p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.ManagementID(), puContext, collector.PolicyDrop, report, packet)
					return false, fmt.Errorf("connection dropped by policy %s: %s", packet.PolicyID, err)
				}

				conn.ReportFlowPolicy = report
				conn.PacketFlowPolicy = packet
				conn.SetState(connection.ServerSendToken)

			case connection.ServerSendToken:
				claims, err := p.tokenaccessor.CreateSynAckPacketToken(puContext, &conn.Auth)
				if err != nil {
					return false, fmt.Errorf("unable to create synack token: %s", err)
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
						return false, err
					}
					msg = append(msg, data[:n]...)
				}
				if _, err := p.tokenaccessor.ParseAckToken(&conn.Auth, msg); err != nil {
					p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.ManagementID(), puContext, collector.InvalidFormat, nil, nil)
					return false, fmt.Errorf("ack packet dropped because signature validation failed %s", err)
				}

				break E
			}
		}
	}

	p.reportAcceptedFlow(flowProperties, conn, conn.Auth.RemoteContextID, puContext.ManagementID(), puContext, conn.ReportFlowPolicy, conn.PacketFlowPolicy)
	return false, nil
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
