package protomux

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/applicationproxy/connproc"
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
}

// NewProtoListener creates a listener for a particular protocol.
func NewProtoListener() *ProtoListener {
	return &ProtoListener{
		connection: make(chan net.Conn),
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
	servicemap      map[string]ListenerType
	defaultListener *ProtoListener
	sync.RWMutex
}

// NewMultiplexedListener returns a new multiplexed listener. Caller
// must register protocols outside of the new object creation.
func NewMultiplexedListener(l net.Listener) *MultiplexedListener {
	return &MultiplexedListener{
		root:       l,
		done:       make(chan struct{}),
		shutdown:   make(chan struct{}),
		wg:         sync.WaitGroup{},
		protomap:   map[ListenerType]*ProtoListener{},
		servicemap: map[string]ListenerType{},
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
	}
	m.protomap[ltype] = p

	return p, nil
}

// UnregisterListener unregisters a listener. It returns an error if there are services
// associated with this listener.
func (m *MultiplexedListener) UnregisterListener(ltype ListenerType) error {
	m.Lock()
	defer m.Unlock()

	for _, l := range m.servicemap {
		if l == ltype {
			return fmt.Errorf("Services using the listener")
		}
	}

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

// RegisterService associates a service (ip, port) with a listener.
func (m *MultiplexedListener) RegisterService(ltype ListenerType, addr string) {
	m.Lock()
	defer m.Unlock()

	m.servicemap[addr] = ltype
}

// UnregisterService unregisters a service. Returns error if the service doesn't exist.
func (m *MultiplexedListener) UnregisterService(addr string) error {
	if _, ok := m.servicemap[addr]; !ok {
		return fmt.Errorf("Service does not exist")
	}

	delete(m.servicemap, addr)

	return nil
}

// Close terminates the server without the context.
func (m *MultiplexedListener) Close() {
	close(m.shutdown)
}

// Serve will demux the connections
func (m *MultiplexedListener) Serve(ctx context.Context) error {
	var wg sync.WaitGroup

	defer func() {
		close(m.done)
		wg.Wait()

		for _, l := range m.protomap {
			close(l.connection)
			// Drain the connections enqueued for the listener.
			for c := range l.connection {
				c.Close()
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
			wg.Add(1)
			go m.serve(c)
		}
	}
}

func (m *MultiplexedListener) serve(c net.Conn) {

	defer m.wg.Done()
	ip, port, err := connproc.GetOriginalDestination(c)
	if err != nil {
		c.Close()
		return
	}

	address := ip.String() + ":" + strconv.Itoa(port)

	m.RLock()
	ltype, ok := m.servicemap[address]
	if !ok {
		c.Close()
		return
	}

	target, ok := m.protomap[ltype]
	if !ok {
		c.Close()
		return
	}
	m.RUnlock()

	select {
	case target.connection <- c:
	case <-m.done:
		c.Close()
	}
}
