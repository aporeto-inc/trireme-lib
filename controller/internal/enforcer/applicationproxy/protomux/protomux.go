package protomux

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/connproc"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/servicecache"
	"go.uber.org/zap"
)

// ListenerType are the types of listeners that can be used.
type ListenerType int

// Values of ListenerType
const (
	TCPApplication ListenerType = iota
	TCPNetwork
	HTTPApplication
	HTTPNetwork
	HTTPSApplication
	HTTPSNetwork
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
	root            net.Listener
	done            chan struct{}
	shutdown        chan struct{}
	wg              sync.WaitGroup
	protomap        map[ListenerType]*ProtoListener
	servicecache    *servicecache.ServiceCache
	defaultListener *ProtoListener
	localIPs        map[string]struct{}
	mark            int
	sync.RWMutex
}

// NewMultiplexedListener returns a new multiplexed listener. Caller
// must register protocols outside of the new object creation.
func NewMultiplexedListener(l net.Listener, mark int) *MultiplexedListener {

	return &MultiplexedListener{
		root:         l,
		done:         make(chan struct{}),
		shutdown:     make(chan struct{}),
		wg:           sync.WaitGroup{},
		protomap:     map[ListenerType]*ProtoListener{},
		servicecache: servicecache.NewTable(),
		localIPs:     connproc.GetInterfaces(),
		mark:         mark,
	}
}

// RegisterListener registers a new listener. It returns the listener that the various
// protocol servers should use. If defaultListener is set, this will become
// the default listener if no match is found. Obviously, there cannot be more
// than one default.
func (m *MultiplexedListener) RegisterListener(ltype ListenerType) (*ProtoListener, error) {
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
func (m *MultiplexedListener) UnregisterListener(ltype ListenerType) error {
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

// NewServiceRegistry creates a new service registry for updates. The caller must
// call SetServiceRegistry to do an atomic update of the service registry.
func (m *MultiplexedListener) NewServiceRegistry() *servicecache.ServiceCache {
	return servicecache.NewTable()
}

// SetServiceRegistry updates the service registry for the caller.
func (m *MultiplexedListener) SetServiceRegistry(s *servicecache.ServiceCache) {
	m.Lock()
	defer m.Unlock()

	m.servicecache = s
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

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-m.shutdown:
			return nil
		default:
			c, err := m.root.Accept()
			if err != nil {
				return err
			}
			m.wg.Add(1)
			go m.serve(c)
		}
	}
}

func (m *MultiplexedListener) serve(conn net.Conn) {

	c, ok := conn.(*markedconn.ProxiedConnection)
	if !ok {
		zap.L().Error("Wrong connection type")
	}

	defer m.wg.Done()
	ip, port := c.GetOriginalDestination()
	local := false
	if _, ok = m.localIPs[networkOfAddress(c.RemoteAddr().String())]; ok {
		local = true
	}

	m.RLock()
	servicecache := m.servicecache
	m.RUnlock()
	entry := servicecache.Find(ip, port, !local)
	if entry == nil {
		// Let's see if we can match the source address.
		// Compatibility with deprecated model. TODO: Remove
		ip = c.RemoteAddr().(*net.TCPAddr).IP
		entry = servicecache.Find(ip, port, !local)
		if entry == nil {
			// Failed with source as well.
			c.Close() // nolint
			return
		}
	}

	ltype := entry.(ListenerType)

	m.RLock()
	target, ok := m.protomap[ltype]
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
	parts := strings.Split(addr, ":")
	if len(parts) == 2 {
		return parts[0]
	}
	return addr
}
