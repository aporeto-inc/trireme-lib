// +build windows

package dnsproxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"

	"github.com/miekg/dns"
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/flowtracking"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/ipsetmanager"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

var clearWindowsDNSCacheFunc = clearWindowsDNSCache

// Proxy struct represents the object for dns proxy
type Proxy struct {
	puFromID   cache.DataStore
	collector  collector.EventCollector
	contextIDs map[string]struct{}
	chreports  chan dnsReport
	sync.RWMutex
}

// New creates an instance of the dns proxy
func New(ctx context.Context, puFromID cache.DataStore, conntrack flowtracking.FlowClient, c collector.EventCollector) *Proxy {
	ch := make(chan dnsReport)
	p := &Proxy{chreports: ch, puFromID: puFromID, collector: c, contextIDs: make(map[string]struct{})}
	go p.reportDNSRequests(ctx, ch)
	return p
}

// StartDNSServer starts the dns server on the port provided for contextID
func (p *Proxy) StartDNSServer(ctx context.Context, contextID, port string) error {
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

// SyncWithPlatformCache is called on policy change.
// Clear the Windows DNS cache in order to guarantee proxying.
func (p *Proxy) SyncWithPlatformCache(ctx context.Context, pctx *pucontext.PUContext) error {

	if pctx.UsesFQDN() {
		return clearWindowsDNSCacheFunc()
	}
	return nil
}

// HandleDNSResponsePacket parses the DNS response and forwards the information to each PU based on policy
func (p *Proxy) HandleDNSResponsePacket(dnsPacketData []byte, sourceIP net.IP, sourcePort uint16, destIP net.IP, destPort uint16, puFromContextID func(string) (*pucontext.PUContext, error)) error {

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
	pus := make([]*pucontext.PUContext, 0, len(p.contextIDs))
	p.Lock()
	for id := range p.contextIDs {
		puCtx, err := puFromContextID(id)
		if err != nil {
			zap.L().Error("dnsproxy: DNS Proxy failed to get PUContext", zap.Error(err))
			continue
		}
		pus = append(pus, puCtx)
	}
	p.Unlock()

	for _, puCtx := range pus {
		ppps, _, err := puCtx.GetPolicyFromFQDN(msg.Question[0].Name)
		if err == nil {
			for _, ppp := range ppps {
				ipsetmanager.V4().UpdateACLIPsets(ips, ppp.Policy.ServiceID)
				ipsetmanager.V6().UpdateACLIPsets(ips, ppp.Policy.ServiceID)
				if err = puCtx.UpdateApplicationACLs(policy.IPRuleList{{Addresses: ips,
					Ports:     ppp.Ports,
					Protocols: ppp.Protocols,
					Policy:    ppp.Policy,
				}}); err != nil {
					zap.L().Error("dnsproxy: adding IP rule returned error", zap.Error(err))
				}
			}
		}

		// source and destination is swapped because we are looking at response packet
		p.reportDNSLookup(msg.Question[0].Name, puCtx, destIP, destPort, sourceIP, sourcePort, ips, "")

		configureDependentServices(puCtx, msg.Question[0].Name, ips)
	}

	return nil
}

func clearWindowsDNSCache() error {
	dnsAPIDll := syscall.NewLazyDLL("dnsapi.dll")
	flushDNSCacheProc := dnsAPIDll.NewProc("DnsFlushResolverCache")
	ret, _, err := flushDNSCacheProc.Call()
	if err != syscall.Errno(0) {
		return err
	}
	if ret == 0 {
		return errors.New("DnsFlushResolverCache failed")
	}
	return nil
}

// Enforce starts enforcing policies for the given policy.PUInfo.
func (p *Proxy) Enforce(ctx context.Context, contextID string, puInfo *policy.PUInfo) error {
	return nil
}

// Unenforce stops enforcing policy for the given IP.
func (p *Proxy) Unenforce(_ context.Context, contextID string) error {
	return nil
}
