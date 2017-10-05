package enforcer

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"go.uber.org/zap"

	"github.com/aporeto-inc/netlink-go/conntrack"
	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme/policy"
)

const (
	SO_ORIGINAL_DST = 80
	proxyMarkInt    = 0x40 //Duplicated from supervisor/iptablesctrl refer to it

)

// Proxy connections from Listen to Backend.
type Proxy struct {
	Listen          string
	Backend         string
	Forward         bool
	Encrypt         bool
	certPath        string
	keyPath         string
	listener        net.Listener
	wg              sync.WaitGroup
	datapath        *Datapath
	socketListeners *cache.Cache
}

type socketListenerEntry struct {
	listen net.Listener
	port   string
}
type sockaddr struct {
	family uint16
	data   [14]byte
}

func NewProxy(listen string, forward bool, encrypt bool, d *Datapath) PolicyEnforcer {
	return &Proxy{
		//Listen:  listen,
		Forward:         forward,
		Encrypt:         encrypt,
		wg:              sync.WaitGroup{},
		datapath:        d,
		socketListeners: cache.NewCache(),
	}
}

func (p *Proxy) Enforce(contextID string, puInfo *policy.PUInfo) error {
	_, err := p.datapath.contextTracker.Get(contextID)
	if err != nil {
		//Start proxy
		errChan := make(chan error, 1)
		port, ok := puInfo.Runtime.Options().Get("proxyPort")
		if !ok {
			zap.L().Error("Port Not Found")
		}
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
			zap.L().Fatal("Fauiled to Bind", zap.Error(err))
			reterr <- err

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
func (p *Proxy) Unenforce(contextID string) error {
	entry, err := p.socketListeners.Get(contextID)
	if err == nil {

		entry.(*socketListenerEntry).listen.Close()
	}
	return nil
}

func (p *Proxy) GetFilterQueue() *fqconfig.FilterQueue {
	return nil
}

func (p *Proxy) Start() error {
	//Do Nothing
	return nil

}
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
			fmt.Println("Failed to get the backend ")
			return
		}
		fmt.Println("I found the right backend", net.IPv4(ip[0], ip[1], ip[2], ip[3]).String(), port)
	}

	downConn, err := p.downConnection(ip, port)
	if err != nil {
		fmt.Println("Failed to connect")
		return
	}

	defer syscall.Close(downConn)

	//Now let us handle the state machine for the down connection
	if err := p.CompleteEndPointAuthorization(string(ip), port, upConn, downConn, contextID); err != nil {
		zap.L().Error("Error on Authorization", zap.Error(err))
		return err
	}
	if !p.Encrypt {
		if err := Pipe(upConn.(*net.TCPConn), downConn); err != nil {
			fmt.Printf("pipe failed: %s", err)
		}
	} else {
		// if err := CopyPipe(upConn, downConn); err != nil {
		// 	fmt.Println("Got an error in pipe ")
		// }
	}
}

func getsockopt(s int, level int, name int, val uintptr, vallen *uint32) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

func setsockopt(s int, level int, name int, val uintptr, vallen uint32) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(vallen), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

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

	fmt.Println("Dialing connection to backend:", net.IPv4(ip[0], ip[1], ip[2], ip[3]).To4(), port)

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
		}

		addr, _ := syscall.Getpeername(fd)
		remote := addr.(*syscall.SockaddrInet4)
		//zap.L().Info("Peer Address", zap.String("IP Address", net.IPv4(remote.Addr[0], remote.Addr[1], remote.Addr[2], remote.Addr[3]).String()))
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
		} else {
			//We are client no advertised port
			return p.StartClientAuthStateMachine(backendip, backendport, upConn, downConn, contextID)

		}

	} else {
		return nil
	}
}

func (p *Proxy) getProxyPort(puInfo *policy.PUInfo) string {
	port, ok := puInfo.Runtime.Options().Get("proxyPort")
	if !ok {
		port = constants.DefaultProxyPort
	}
	return port
}

func (p *Proxy) StartClientAuthStateMachine(backendip string, backendport uint16, upConn net.Conn, downConn int, contextID string) error {
	//We are running on top of TCP nothing should be lost or come out of order makes the state machines easy....
	puContext, err := p.datapath.contextTracker.Get(contextID)
	if err != nil {
		zap.L().Error("Did not find context")
	}
	conn := NewTCPConnection()

	toAddr, err := syscall.Getpeername(downConn)
	//fmt.Println(toAddr.(*syscall.SockaddrInet4).)
	// ipv4addr := toAddr.(*syscall.SockaddrInet4).Addr
	// port := toAddr.(*syscall.SockaddrInet4).Port
	if err != nil {
		zap.L().Error("Peer Name Failed", zap.Error(err))
	}

L:
	for conn.GetState() == TCPSynSend {
		msg := make([]byte, 1024)
		for {
			zap.L().Error("Conn State", zap.Int("State", int(conn.GetState())))
			switch conn.GetState() {
			case TCPSynSend:
				token, err := p.datapath.createSynPacketToken(puContext.(*PUContext), &conn.Auth)
				if err != nil {
					zap.L().Error("Failed to create syn token", zap.Error(err))
				}
				if serr := syscall.Sendto(downConn, token, 0, toAddr); serr != nil {
					zap.L().Error("Sendto failed", zap.Error(serr))
					return serr
				}
				conn.SetState(TCPSynAckReceived)

			case TCPSynAckReceived:
				// plc, err := puContext.(*PUContext).ApplicationACLs.GetMatchingAction(ipv4addr[:], uint16(port))
				// if err != nil || plc.Action&policy.Reject > 0 {
				// 	zap.L().Error("Error", zap.Error(err))
				// 	zap.L().Error("Action", zap.Int("Action", int(plc.Action)))
				// 	return fmt.Errorf("No Auth or ACLs - Drop SynAck packet and connection")
				// }
				n, _, err := syscall.Recvfrom(downConn, msg, 0)
				if err != nil {
					zap.L().Error("Received Ack", zap.Error(err))
					return err
				}
				msg = msg[:n]
				claims, err := p.datapath.parsePacketToken(&conn.Auth, msg)
				if err != nil || claims == nil {
					return fmt.Errorf("Synack packet dropped because of bad claims %v", claims)
				}
				if index, _ := puContext.(*PUContext).RejectTxtRules.Search(claims.T); p.datapath.mutualAuthorization && index >= 0 {
					return fmt.Errorf("Dropping because of reject rule on transmitter")
				}
				if index, _ := puContext.(*PUContext).AcceptTxtRules.Search(claims.T); !p.datapath.mutualAuthorization || index < 0 {
					return fmt.Errorf("Dropping because of reject rule on receiver")
				}
				conn.SetState(TCPAckSend)

			case TCPAckSend:
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

func (p *Proxy) StartServerAuthStateMachine(backendip string, backendport uint16, upConn net.Conn, downConn int, contextID string) error {
	context, err := p.datapath.contextTracker.Get(contextID)
	if err != nil {
		zap.L().Error("Did not find context")
	}
	conn := NewTCPConnection()
	conn.SetState(TCPSynReceived)
E:
	for conn.GetState() == TCPSynReceived {
		for {
			msg := []byte{}

			switch conn.GetState() {
			case TCPSynReceived:
				for {
					data := make([]byte, 1024)
					n, err := upConn.Read(data)
					if n < 1024 || err == nil {
						zap.L().Error("Received Bytes", zap.Int("NumBytes", n), zap.Error(err))
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
					return err
				}
				claims.T.AppendKeyValue(PortNumberLabelString, strconv.Itoa(int(backendport)))
				if index, plc := context.(*PUContext).RejectRcvRules.Search(claims.T); index >= 0 {
					zap.L().Error("Connection Dropped", zap.String("Policy ID", plc.(*policy.FlowPolicy).PolicyID))
					return fmt.Errorf("Connection dropped because of Policy %v", err)
				}
				if index, _ := context.(*PUContext).AcceptRcvRules.Search(claims.T); index < 0 {

					return fmt.Errorf("Connection dropped because No Accept Policy")
				}
				t := strings.Join(claims.T.GetSlice(), ",")
				zap.L().Error("Accepted Tokens", zap.String("tokens", t))
				conn.SetState(TCPSynAckSend)

			case TCPSynAckSend:
				zap.L().Error("TCPSYNACKSEND ENTER")
				//context.(*PUContext).Lock()
				claims, err := p.datapath.createSynAckPacketToken(context.(*PUContext), &conn.Auth)
				//context.(*PUContext).Unlock()
				if err != nil {
					return fmt.Errorf("Unable to create synack token")
				}
				zap.L().Error("Called Write")
				synackn, err := upConn.Write(claims)
				if err == nil {
					zap.L().Error("Returned SynACK Token size", zap.Int("Token Length", synackn))
				} else {
					zap.L().Error("Failed to write", zap.Error(err))
				}
				conn.SetState(TCPAckProcessed)
				zap.L().Error("TCPSYNACKSEND EXIT")
			case TCPAckProcessed:
				for {
					data := make([]byte, 1024)
					n, err := upConn.Read(data)
					if n < 1024 || err == nil {
						zap.L().Error("Received Bytes", zap.Int("NumBytes", n), zap.Error(err))
						msg = append(msg, data[:n]...)
						break
					}
					if err != nil {
						return err
					}
					msg = append(msg, data[:n]...)
				}
				if _, err := p.datapath.parseAckToken(&conn.Auth, msg); err != nil {
					return fmt.Errorf("Ack packet dropped because signature validation failed %v", err)
				}
				break E
			}
		}
	}
	//zap.L().Error("Received", zap.String("Message", hex.Dump(msg)))
	//upConn.Write([]byte("Good"))
	return nil

}
