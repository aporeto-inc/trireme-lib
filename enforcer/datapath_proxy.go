package enforcer

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"go.uber.org/zap"

	"github.com/aporeto-inc/netlink-go/conntrack"
	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme/policy"
)

const (
	SO_ORIGINAL_DST = 80   //nolint
	proxyMarkInt    = 0x40 //Duplicated from supervisor/iptablesctrl refer to it

)

// Proxy connections from Listen to Backend.
type Proxy struct {
	Listen   string
	Backend  string
	Forward  bool
	Encrypt  bool
	certPath string
	keyPath  string
	//listener        net.Listener
	wg              sync.WaitGroup
	datapath        *Datapath
	socketListeners *cache.Cache
	IPList          []string
}

// ProxyFlowProperties is a struct used to pass flow information up
type ProxyFlowProperties struct {
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

//NewProxy -- Create a new instance of Proxy
func NewProxy(listen string, forward bool, encrypt bool, d *Datapath) PolicyEnforcer {
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
		//Listen:  listen,
		Forward:         forward,
		Encrypt:         encrypt,
		wg:              sync.WaitGroup{},
		datapath:        d,
		socketListeners: cache.NewCache("socketlisterner"),
		IPList:          iplist,
	}
}

//Enforce -- Enforce function policyenforcer interface
func (p *Proxy) Enforce(contextID string, puInfo *policy.PUInfo) error {
	_, err := p.datapath.contextTracker.Get(contextID)

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
	//Nothing required for the update case we will use the parent datapath structures to store state about PU
	return nil

}

//StartListener returns error only during init. After init it never returns
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
				conn.Close()
			}()
		} else {
			return
		}

	}
}

//Unenforce - Unenforce from the policyenforcer interfaces
func (p *Proxy) Unenforce(contextID string) error {
	entry, err := p.socketListeners.Get(contextID)
	if err == nil {
		entry.(*socketListenerEntry).listen.Close()
	}
	//p.socketListeners.Remove(contextID)
	return nil
}

//GetFilterQueue -- PolicyEnforcer interface function not required here implemented for interface
func (p *Proxy) GetFilterQueue() *fqconfig.FilterQueue {
	return nil
}

//Start -- Does nothing we do proxy start on an enforce when we know the port
func (p *Proxy) Start() error {
	//Do Nothing
	return nil

}

//Stop -- Wait for go routine to exit . From policyenforcer interface
func (p *Proxy) Stop() error {
	p.wg.Wait()
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
	defer upConn.Close()

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
			syscall.Close(downConn)
		}
		return
	}

	defer syscall.Close(downConn)

	//Now let us handle the state machine for the down connection
	if err := p.CompleteEndPointAuthorization(string(ip), port, upConn, downConn, contextID); err != nil {
		zap.L().Error("Error on Authorization", zap.Error(err))
		return
	}
	if !p.Encrypt {
		if err := Pipe(upConn.(*net.TCPConn), downConn); err != nil {
			fmt.Printf("pipe failed: %s", err)
		}
	}
}

func getsockopt(s int, level int, name int, val uintptr, vallen *uint32) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

//getOriginalDestination -- Func to get original destination of redirected packet. Used to figure out backend destination
func getOriginalDestination(conn net.Conn) ([]byte, uint16, error) {
	var addr sockaddr
	size := uint32(unsafe.Sizeof(addr))

	inFile, err := conn.(*net.TCPConn).File()
	if err != nil {
		return []byte{}, 0, err
	}

	err = getsockopt(int(inFile.Fd()), syscall.SOL_IP, SO_ORIGINAL_DST, uintptr(unsafe.Pointer(&addr)), &size)
	if err != nil {
		return []byte{}, 0, err
	}

	var ip net.IP
	if addr.family != syscall.AF_INET {
		return []byte{}, 0, fmt.Errorf("Invalid address family")

	}

	ip = addr.data[2:6]
	port := uint16(int(addr.data[0])<<8 + int(addr.data[1]))

	return ip, port, nil
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

//CompleteEndPointAuthorization -- Aporeto Handshake on top of a completed connection
//We will define states here equivalent to SYN_SENT AND SYN_RECEIVED
func (p *Proxy) CompleteEndPointAuthorization(backendip string, backendport uint16, upConn net.Conn, downConn int, contextID string) error {
	puContext, err := p.datapath.contextTracker.Get(contextID)
	if err != nil {
		zap.L().Error("Did not find context")
	}
	puContext.(*PUContext).Lock()
	defer puContext.(*PUContext).Unlock()
	pu := puContext.(*PUContext)
	//addr := upConn.RemoteAddr().String()

	if pu.PUType == constants.LinuxProcessPU {
		//Are we client or server proxy

		if len(puContext.(*PUContext).Ports) > 0 && puContext.(*PUContext).Ports[0] != "0" {
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
func (p *Proxy) StartClientAuthStateMachine(backendip string, backendport uint16, upConn net.Conn, downConn int, contextID string) error {
	//We are running on top of TCP nothing should be lost or come out of order makes the state machines easy....
	puContext, err := p.datapath.contextTracker.Get(contextID)
	if err != nil {
		zap.L().Error("Did not find context")
	}
	conn := NewProxyConnection()
	toAddr, _ := syscall.Getpeername(downConn)
	localaddr, _ := syscall.Getsockname(downConn)
	localinet4ip, _ := localaddr.(*syscall.SockaddrInet4)
	remoteinet4ip, _ := toAddr.(*syscall.SockaddrInet4)
	flowProperties := &ProxyFlowProperties{
		SourceIP:   net.IPv4(localinet4ip.Addr[0], localinet4ip.Addr[1], localinet4ip.Addr[2], localinet4ip.Addr[3]),
		DestIP:     net.IPv4(remoteinet4ip.Addr[0], remoteinet4ip.Addr[1], remoteinet4ip.Addr[2], remoteinet4ip.Addr[3]),
		SourcePort: uint16(localinet4ip.Port),
		DestPort:   uint16(remoteinet4ip.Port),
	}

L:
	for conn.GetState() == ClientTokenSend {
		msg := make([]byte, 1024)
		for {
			switch conn.GetState() {
			case ClientTokenSend:
				token, err := p.datapath.createSynPacketToken(puContext.(*PUContext), &conn.Auth)
				if err != nil {
					zap.L().Error("Failed to create syn token", zap.Error(err))
				}

				if serr := syscall.Sendto(downConn, token, 0, toAddr); serr != nil {
					zap.L().Error("Sendto failed", zap.Error(serr))
					return serr
				}
				conn.SetState(ClientPeerTokenReceive)

			case ClientPeerTokenReceive:

				n, _, err := syscall.Recvfrom(downConn, msg, 0)
				if err != nil {
					zap.L().Error("Error while receiving peer token", zap.Error(err))
					return err
				}

				msg = msg[:n]
				claims, err := p.datapath.parsePacketToken(&conn.Auth, msg)
				if err != nil || claims == nil {
					p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.(*PUContext).ManagementID, puContext.(*PUContext), collector.InvalidToken, nil)
					return fmt.Errorf("Peer token reject because of bad claims %v", claims)
				}

				if index, _ := puContext.(*PUContext).RejectTxtRules.Search(claims.T); p.datapath.mutualAuthorization && index >= 0 {
					p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.(*PUContext).ManagementID, puContext.(*PUContext), collector.PolicyDrop, nil)
					return fmt.Errorf("Dropping because of reject rule on transmitter")
				}
				if index, _ := puContext.(*PUContext).AcceptTxtRules.Search(claims.T); !p.datapath.mutualAuthorization || index < 0 {
					p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.(*PUContext).ManagementID, puContext.(*PUContext), collector.PolicyDrop, nil)
					return fmt.Errorf("Dropping because of reject rule on receiver")
				}
				conn.SetState(ClientSendSignedPair)

			case ClientSendSignedPair:
				token, err := p.datapath.createAckPacketToken(puContext.(*PUContext), &conn.Auth)
				if err != nil {
					zap.L().Error("Failed to create ack token", zap.Error(err))
				}
				if serr := syscall.Sendto(downConn, token, 0, toAddr); serr != nil {
					zap.L().Error("Sendto failed", zap.Error(serr))
					return serr
				}
				break L
			}

		}
	}
	return nil

}

//StartServerAuthStateMachine -- Start the aporeto handshake for a server application
func (p *Proxy) StartServerAuthStateMachine(backendip string, backendport uint16, upConn io.ReadWriter, downConn int, contextID string) error {
	puContext, err := p.datapath.contextTracker.Get(contextID)
	if err != nil {
		zap.L().Error("Did not find context")
	}
	toAddr, _ := syscall.Getpeername(downConn)
	localaddr, _ := syscall.Getsockname(downConn)
	localinet4ip, _ := localaddr.(*syscall.SockaddrInet4)
	remoteinet4ip, _ := toAddr.(*syscall.SockaddrInet4)
	flowProperties := &ProxyFlowProperties{
		SourceIP:   net.IPv4(localinet4ip.Addr[0], localinet4ip.Addr[1], localinet4ip.Addr[2], localinet4ip.Addr[3]),
		DestIP:     net.IPv4(remoteinet4ip.Addr[0], remoteinet4ip.Addr[1], remoteinet4ip.Addr[2], remoteinet4ip.Addr[3]),
		SourcePort: uint16(localinet4ip.Port),
		DestPort:   uint16(remoteinet4ip.Port),
	}
	conn := NewProxyConnection()
	conn.SetState(ServerReceivePeerToken)
E:
	for conn.GetState() == ServerReceivePeerToken {
		for {
			msg := []byte{}

			switch conn.GetState() {
			case ServerReceivePeerToken:
				for {
					data := make([]byte, 1024)
					n, err := upConn.Read(data)
					if n < 1024 || err == nil {
						msg = append(msg, data[:n]...)
						break
					}
					if err != nil {
						return err
					}
					msg = append(msg, data[:n]...)
				}
				claims, err := p.datapath.parsePacketToken(&conn.Auth, msg)
				if err != nil || claims == nil {
					p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.(*PUContext).ManagementID, puContext.(*PUContext), collector.InvalidToken, nil)
					zap.L().Error("REPORTED FLOW REJECTED")
					return err
				}
				claims.T.AppendKeyValue(PortNumberLabelString, strconv.Itoa(int(backendport)))
				if index, plc := puContext.(*PUContext).RejectRcvRules.Search(claims.T); index >= 0 {
					zap.L().Error("Connection Dropped", zap.String("Policy ID", plc.(*policy.FlowPolicy).PolicyID))
					p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.(*PUContext).ManagementID, puContext.(*PUContext), collector.PolicyDrop, plc.(*policy.FlowPolicy))
					return fmt.Errorf("Connection dropped because of Policy %v", err)
				}
				var action interface{}
				if index, action = puContext.(*PUContext).AcceptRcvRules.Search(claims.T); index < 0 {

					p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.(*PUContext).ManagementID, puContext.(*PUContext), collector.PolicyDrop, nil)
					return fmt.Errorf("Connection dropped because No Accept Policy")
				}
				conn.FlowPolicy = action.(*policy.FlowPolicy)
				conn.SetState(ServerSendToken)

			case ServerSendToken:
				claims, err := p.datapath.createSynAckPacketToken(puContext.(*PUContext), &conn.Auth)
				if err != nil {
					return fmt.Errorf("Unable to create synack token")
				}
				synackn, err := upConn.Write(claims)
				if err == nil {
					zap.L().Error("Returned SynACK Token size", zap.Int("Token Length", synackn))
				} else {
					zap.L().Error("Failed to write", zap.Error(err))
				}
				conn.SetState(ServerAuthenticatePair)
			case ServerAuthenticatePair:
				for {
					data := make([]byte, 1024)
					n, err := upConn.Read(data)
					if n < 1024 || err == nil {
						msg = append(msg, data[:n]...)
						break
					}
					if err != nil {
						return err
					}
					msg = append(msg, data[:n]...)
				}
				if _, err := p.datapath.parseAckToken(&conn.Auth, msg); err != nil {
					p.reportRejectedFlow(flowProperties, conn, collector.DefaultEndPoint, puContext.(*PUContext).ManagementID, puContext.(*PUContext), collector.InvalidFormat, nil)
					return fmt.Errorf("Ack packet dropped because signature validation failed %v", err)
				}

				break E
			}
		}
	}

	p.reportAcceptedFlow(flowProperties, conn, conn.Auth.RemoteContextID, puContext.(*PUContext).ManagementID, puContext.(*PUContext), conn.FlowPolicy)
	return nil

}

func (p *Proxy) reportAcceptedFlow(flowproperties *ProxyFlowProperties, conn *ProxyConnection, sourceID string, destID string, context *PUContext, plc *policy.FlowPolicy) {
	//conn.Reported = true
	p.datapath.reportProxiedFlow(flowproperties, conn, sourceID, destID, context, "N/A", plc)
}

func (p *Proxy) reportRejectedFlow(flowproperties *ProxyFlowProperties, conn *ProxyConnection, sourceID string, destID string, context *PUContext, mode string, plc *policy.FlowPolicy) {

	if plc == nil {
		plc = &policy.FlowPolicy{
			Action:   policy.Reject,
			PolicyID: "",
		}
	}
	p.datapath.reportProxiedFlow(flowproperties, conn, sourceID, destID, context, mode, plc)

}
