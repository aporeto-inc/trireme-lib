// +build linux 

package dnsproxy

import (
	"context"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/pkg/flowtracking"
	"go.aporeto.io/trireme-lib/controller/pkg/ipsetmanager"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

// Proxy struct represents the object for dns proxy
type Proxy struct {
	puFromID          cache.DataStore
	conntrack         flowtracking.FlowClient
	collector         collector.EventCollector
	contextIDToServer map[string]*dns.Server
	chreports         chan dnsReport
	updateIPsets      ipsetmanager.ACLManager
	sync.RWMutex
}

type serveDNS struct {
	contextID string
	*Proxy
}

const (
	dnsRequestTimeout = 2 * time.Second
	proxyMarkInt      = 0x40 //Duplicated from supervisor/iptablesctrl refer to it
)

func socketOptions(_, _ string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, proxyMarkInt); err != nil {
			zap.L().Error("Failed to mark connection", zap.Error(err))
		}
	})

	if err != nil {
		return err
	}

	return opErr
}

func listenUDP(network, addr string) (net.PacketConn, error) {
	var lc net.ListenConfig

	lc.Control = socketOptions

	return lc.ListenPacket(context.Background(), network, addr)
}

func forwardDNSReq(r *dns.Msg, ip net.IP, port uint16) (*dns.Msg, []string, error) {
	var ips []string
	c := new(dns.Client)
	c.Dialer = &net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, proxyMarkInt); err != nil {
					zap.L().Error("Failed to assing mark to socket", zap.Error(err))
				}
			})
		},
		Timeout: dnsRequestTimeout,
	}

	in, _, err := c.Exchange(r, net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
	if err != nil {
		return nil, nil, err
	}

	for _, ans := range in.Answer {
		if ans.Header().Rrtype == dns.TypeA {
			t, _ := ans.(*dns.A)
			ips = append(ips, t.A.String())
		}

		if ans.Header().Rrtype == dns.TypeAAAA {
			t, _ := ans.(*dns.AAAA)
			ips = append(ips, t.AAAA.String())
		}
	}

	return in, ips, nil
}

func (s *serveDNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	var err error
	lAddr := w.LocalAddr().(*net.UDPAddr)
	rAddr := w.RemoteAddr().(*net.UDPAddr)
	var puCtx *pucontext.PUContext

	defer func() {
		if puCtx != nil {
			s.reportDNSLookup(r.Question[0].Name, puCtx, rAddr.IP, "")
		}
	}()

	origIP, origPort, _, err := s.conntrack.GetOriginalDest(net.ParseIP("127.0.0.1"), rAddr.IP, uint16(lAddr.Port), uint16(rAddr.Port), 17)
	if err != nil {
		zap.L().Error("Failed to find flow for the redirected dns traffic", zap.Error(err))
		return
	}

	data, err := s.puFromID.Get(s.contextID)
	if err != nil {
		zap.L().Error("context not found for the PU with ID", zap.String("contextID", s.contextID))
		return
	}

	dnsReply, ips, err := forwardDNSReq(r, origIP, origPort)
	if err != nil {
		zap.L().Debug("Forwarded dns request returned error", zap.Error(err))
		return
	}

	puCtx = data.(*pucontext.PUContext)
	ps, err1 := puCtx.GetPolicyFromFQDN(r.Question[0].Name)
	if err1 == nil {
		for _, p := range ps {
			s.updateIPsets.UpdateIPsets(ips, p.Policy.ServiceID)
			if err1 := puCtx.UpdateApplicationACLs(policy.IPRuleList{{Addresses: ips,
				Ports:     p.Ports,
				Protocols: p.Protocols,
				Policy:    p.Policy,
			}}); err1 != nil {
				zap.L().Error("Adding IP rule returned error", zap.Error(err1))
			}
		}
	}

	if err = w.WriteMsg(dnsReply); err != nil {
		zap.L().Error("Writing dns response back to the client returned error", zap.Error(err))
	}
}

// StartDNSServer starts the dns server on the port provided for contextID
func (p *Proxy) StartDNSServer(contextID, port string) error {
	netPacketConn, err := listenUDP("udp", "127.0.0.1:"+port)
	if err != nil {
		return err
	}

	var server *dns.Server

	storeInMap := func() {
		p.Lock()
		defer p.Unlock()

		p.contextIDToServer[contextID] = server
	}

	server = &dns.Server{NotifyStartedFunc: storeInMap, PacketConn: netPacketConn, Handler: &serveDNS{contextID, p}}

	go func() {
		if err := server.ActivateAndServe(); err != nil {
			zap.L().Error("Could not start DNS proxy server", zap.Error(err))
		}
	}()

	return nil
}

// ShutdownDNS shuts down the dns server for contextID
func (p *Proxy) ShutdownDNS(contextID string) {
	p.Lock()
	defer p.Unlock()
	if s, ok := p.contextIDToServer[contextID]; ok {
		if err := s.Shutdown(); err != nil {
			zap.L().Error("shutdown of dns server returned error", zap.String("contextID", contextID), zap.Error(err))
		}
		delete(p.contextIDToServer, contextID)
	}
}

// New creates an instance of the dns proxy
func New(puFromID cache.DataStore, conntrack flowtracking.FlowClient, c collector.EventCollector, aclmanager ipsetmanager.ACLManager) *Proxy {
	ch := make(chan dnsReport)
	p := &Proxy{chreports: ch, puFromID: puFromID, collector: c, conntrack: conntrack, contextIDToServer: map[string]*dns.Server{}, updateIPsets: aclmanager}
	go p.reportDNSRequests(ch)
	return p
}
