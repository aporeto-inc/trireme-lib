package dnsproxy

import (
	"net"
	"sync"

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
	puFromID     cache.DataStore
	collector    collector.EventCollector
	contextIDs   map[string]struct{}
	chreports    chan dnsReport
	updateIPsets ipsetmanager.ACLManager
	sync.RWMutex
}

// New creates an instance of the dns proxy
func New(puFromID cache.DataStore, conntrack flowtracking.FlowClient, c collector.EventCollector, aclmanager ipsetmanager.ACLManager) *Proxy {
	ch := make(chan dnsReport)
	p := &Proxy{chreports: ch, puFromID: puFromID, collector: c, contextIDs: make(map[string]struct{}), updateIPsets: aclmanager}
	go p.reportDNSRequests(ch)
	return p
}

// StartDNSServer starts the dns server on the port provided for contextID
func (p *Proxy) StartDNSServer(contextID, port string) error {
	p.Lock()
	defer p.Unlock()
	p.contextIDs[contextID] = struct{}{}
	return nil
}

// ShutdownDNS shuts down the dns server for contextID
func (p *Proxy) ShutdownDNS(contextID string) {
	p.Lock()
	defer p.Unlock()
	delete(p.contextIDs, contextID)
}

// HandleDNSResponsePacket parses the DNS response and forwards the information to each PU based on policy
func (p *Proxy) HandleDNSResponsePacket(dnsPacketData []byte, serverIP net.IP, puFromContextID func(string) (*pucontext.PUContext, error)) error {

	// parse dns
	msg := &dns.Msg{}
	err := msg.Unpack(dnsPacketData)
	if err != nil {
		return err
	}

	// Make sure we have a question
	if len(msg.Question) <= 0 {
		return nil
	}

	var ips []string
	for _, ans := range msg.Answer {
		if ans.Header().Rrtype == dns.TypeA {
			t, _ := ans.(*dns.A)
			ips = append(ips, t.A.String())
		}

		if ans.Header().Rrtype == dns.TypeAAAA {
			t, _ := ans.(*dns.AAAA)
			ips = append(ips, t.AAAA.String())
		}
	}

	// let each pu handle it
	var pus []*pucontext.PUContext
	p.Lock()
	for id, _ := range p.contextIDs {
		puCtx, err := puFromContextID(id)
		if err != nil {
			zap.L().Error("DNS Proxy failed to get PUContext", zap.Error(err))
			continue
		}
		pus = append(pus, puCtx)
	}
	p.Unlock()

	for _, puCtx := range pus {
		ppps, err := puCtx.GetPolicyFromFQDN(msg.Question[0].Name)
		if err == nil {
			for _, ppp := range ppps {
				p.updateIPsets.UpdateIPsets(ips, ppp.Policy.ServiceID)
				if err = puCtx.UpdateApplicationACLs(policy.IPRuleList{{Addresses: ips,
					Ports:     ppp.Ports,
					Protocols: ppp.Protocols,
					Policy:    ppp.Policy,
				}}); err != nil {
					zap.L().Error("Adding IP rule returned error", zap.Error(err))
				}
			}
			p.reportDNSLookup(msg.Question[0].Name, puCtx, serverIP, "")
		}
	}

	return nil
}
