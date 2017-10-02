package enforcer

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"syscall"
	"unsafe"

	"go.uber.org/zap"

	"github.com/aporeto-inc/netlink-go/conntrack"
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
	Listen   string
	Backend  string
	Forward  bool
	Encrypt  bool
	certPath string
	keyPath  string
	listener net.Listener
	wg       sync.WaitGroup
}

type sockaddr struct {
	family uint16
	data   [14]byte
}

func NewProxy(listen string, forward bool, encrypt bool) PolicyEnforcer {
	return &Proxy{
		Listen:  listen,
		Forward: forward,
		Encrypt: encrypt,
		wg:      sync.WaitGroup{},
	}
}
func (p *Proxy) Enforce(contextID string, puInfo *policy.PUInfo) error {
	return nil

}

func (p *Proxy) Unenforce(contextID string) error {
	return nil
}

func (p *Proxy) GetFilterQueue() *fqconfig.FilterQueue {
	return nil
}

func (p *Proxy) Start() error {
	var err error

	if p.Forward || !p.Encrypt {
		if p.listener, err = net.Listen("tcp", p.Listen); err != nil {
			zap.L().Fatal("Fauiled to Bind", zap.Error(err))
			return err
		}

	} else {
		config, err := p.loadTLS()
		if err != nil {
			return err
		}

		if p.listener, err = tls.Listen("tcp", p.Listen, config); err != nil {
			return err
		}
	}
	zap.L().Error("Started Proxy")
	for {
		if conn, err := p.listener.Accept(); err == nil {
			zap.L().Error("Got Connection")
			filehdl, _ := conn.(*net.TCPConn).File()
			err = syscall.SetsockoptInt(int(filehdl.Fd()), syscall.SOL_SOCKET, syscall.SO_MARK, proxyMarkInt)

			if err != nil {
				zap.L().Error(err.Error())
			}

			zap.L().Error("Accepted connection")
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				p.handle(conn)
				conn.Close()
			}()
		} else {
			return nil
		}
	}

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
func (p *Proxy) handle(upConn net.Conn) {
	var err error

	var ip []byte
	var port uint16
	defer upConn.Close()

	backend := p.Backend
	if p.Forward {
		ip, port, err = getOriginalDestination(upConn)
		if err != nil {
			fmt.Println("Failed to get the backend ")
			return
		}
		fmt.Println("I found the right backend", backend)
	}

	downConn, err := p.downConnection(ip, port)
	if err != nil {
		fmt.Println("Failed to connect")
		return
	}

	defer syscall.Close(downConn)

	//Now let us handle the state machine for the down connection
	// if err := p.CompleteEndPointAuthorization(backend, upConn, downConn); err != nil {
	// 	return
	// }
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
		zap.L().Info("Sock Address", zap.String("IP Address", net.IPv4(local.Addr[0], local.Addr[1], local.Addr[2], local.Addr[3]).String()), zap.Int("Port", local.Port))

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
func (p *Proxy) CompleteEndPointAuthorization(backend string, upConn, downConn net.Conn) error {
	return nil
}
