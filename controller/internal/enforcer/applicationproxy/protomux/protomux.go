package protomux

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/common"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/serviceregistry"
	"go.uber.org/zap"
)

// ProtoListener is
type ProtoListener struct {
	net.Listener
	connection chan net.Conn
	mark       int
}

// NewProtoListener creates a listener for a particular protocol.
func NewProtoListener(mark int) *ProtoListener {
	return &ProtoListener{
		connection: make(chan net.Conn),
		mark:       mark,
	}
}

// Accept accepts new connections over the channel.
func (p *ProtoListener) Accept() (net.Conn, error) {
	c, ok := <-p.connection
	if !ok {
		return nil, fmt.Errorf("mux: listener closed")
	}
	return c, nil
}

// MultiplexedListener is the root listener that will split
// connections to different protocols.
type MultiplexedListener struct {
	root     net.Listener
	done     chan struct{}
	shutdown chan struct{}
	wg       sync.WaitGroup
	protomap map[common.ListenerType]*ProtoListener
	puID     string

	defaultListener *ProtoListener
	localIPs        map[string]struct{}
	mark            int
	registry        *serviceregistry.Registry
	sync.RWMutex
}

// NewMultiplexedListener returns a new multiplexed listener. Caller
// must register protocols outside of the new object creation.
func NewMultiplexedListener(l net.Listener, mark int, registry *serviceregistry.Registry, puID string) *MultiplexedListener {

	return &MultiplexedListener{
		root:     l,
		done:     make(chan struct{}),
		shutdown: make(chan struct{}),
		wg:       sync.WaitGroup{},
		protomap: map[common.ListenerType]*ProtoListener{},
		registry: registry,
		localIPs: markedconn.GetInterfaces(),
		mark:     mark,
		puID:     puID,
	}
}

// RegisterListener registers a new listener. It returns the listener that the various
// protocol servers should use. If defaultListener is set, this will become
// the default listener if no match is found. Obviously, there cannot be more
// than one default.
func (m *MultiplexedListener) RegisterListener(ltype common.ListenerType) (*ProtoListener, error) {
	m.Lock()
	defer m.Unlock()

	if _, ok := m.protomap[ltype]; ok {
		return nil, fmt.Errorf("Cannot register same listener type multiple times")
	}

	p := &ProtoListener{
		Listener:   m.root,
		connection: make(chan net.Conn),
		mark:       m.mark,
	}
	m.protomap[ltype] = p

	return p, nil
}

// UnregisterListener unregisters a listener. It returns an error if there are services
// associated with this listener.
func (m *MultiplexedListener) UnregisterListener(ltype common.ListenerType) error {
	m.Lock()
	defer m.Unlock()

	delete(m.protomap, ltype)

	return nil
}

// RegisterDefaultListener registers a default listener.
func (m *MultiplexedListener) RegisterDefaultListener(p *ProtoListener) error {
	m.Lock()
	defer m.Unlock()

	if m.defaultListener != nil {
		return fmt.Errorf("Default listener already registered")
	}

	m.defaultListener = p
	return nil
}

// UnregisterDefaultListener unregisters the default listener.
func (m *MultiplexedListener) UnregisterDefaultListener() error {
	m.Lock()
	defer m.Unlock()

	if m.defaultListener == nil {
		return fmt.Errorf("No default listener registered")
	}

	m.defaultListener = nil

	return nil
}

// Close terminates the server without the context.
func (m *MultiplexedListener) Close() {
	close(m.shutdown)
}

// Serve will demux the connections
func (m *MultiplexedListener) Serve(ctx context.Context) error {

	defer func() {
		close(m.done)
		m.wg.Wait()

		m.RLock()
		defer m.RUnlock()

		for _, l := range m.protomap {
			close(l.connection)
			// Drain the connections enqueued for the listener.
			for c := range l.connection {
				c.Close() // nolint
			}
		}
	}()

	go func() {
		for {
			select {
			case <-time.After(5 * time.Second):
				m.Lock()
				m.localIPs = markedconn.GetInterfaces()
				m.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-m.shutdown:
			return nil
		default:

			c, err := m.root.Accept()
			if err != nil {
				// check if the error is due to shutdown in progress
				select {
				case <-m.shutdown:
					return nil
				default:
				}
				// if it is an actual error (which can happen in Windows we can't get origin ip/port from our driver),
				// then log an error and continue accepting connections.
				zap.L().Error("error from Accept", zap.Error(err))
				break
			}
			m.wg.Add(1)
			go m.serve(c)
		}
	}
}

func (m *MultiplexedListener) serve(conn net.Conn) {
	defer m.wg.Done()

	c, ok := conn.(*markedconn.ProxiedConnection)
	if !ok {
		zap.L().Error("Wrong connection type")
		return
	}

	ip, port := c.GetOriginalDestination()
	remoteAddr := c.RemoteAddr()
	if remoteAddr == nil {
		zap.L().Error("Connection remote address cannot be found. Abort")
		return
	}

	local := false
	m.Lock()
	localIPs := m.localIPs
	m.Unlock()
	if _, ok = localIPs[networkOfAddress(remoteAddr.String())]; ok {
		local = true
	}

	var listenerType common.ListenerType
	if local {
		_, serviceData, err := m.registry.RetrieveServiceDataByIDAndNetwork(m.puID, ip, port, "")
		if err != nil {
			zap.L().Error("Cannot discover target service",
				zap.String("ContextID", m.puID),
				zap.String("ip", ip.String()),
				zap.Int("port", port),
				zap.String("Remote IP", remoteAddr.String()),
				zap.Error(err),
			)
			return
		}
		listenerType = serviceData.ServiceType
	} else {
		pctx, err := m.registry.RetrieveExposedServiceContext(ip, port, "")
		if err != nil {
			zap.L().Error("Cannot discover target service",
				zap.String("ip", ip.String()),
				zap.Int("port", port),
				zap.String("Remote IP", remoteAddr.String()),
			)
			return
		}

		listenerType = pctx.Type
	}

	m.RLock()
	target, ok := m.protomap[listenerType]
	m.RUnlock()
	if !ok {
		c.Close() // nolint
		return
	}

	select {
	case target.connection <- c:
	case <-m.done:
		c.Close() // nolint
	}
}

func networkOfAddress(addr string) string {
	ip, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}

	return ip
}
