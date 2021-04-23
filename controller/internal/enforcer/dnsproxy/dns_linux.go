// +build linux

package dnsproxy

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/counters"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/flowtracking"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/ipsetmanager"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

// removeExpiredEntryFunc is the type of the function that gets called when an IP entry expires (when its TTL hits 0)
type removeExpiredEntryFunc func(string)

// Proxy struct represents the object for dns proxy
type Proxy struct {
	puFromID                 cache.DataStore
	conntrack                flowtracking.FlowClient
	collector                collector.EventCollector
	contextIDToServer        map[string]*dns.Server
	chreports                chan dnsReport
	contextIDToDNSNames      *cache.Cache
	contextIDToDNSNamesLocks *mutexMap
	IPToTTL                  *cache.Cache
	IPToTTLLocks             *mutexMap
	removeExpiredEntry       removeExpiredEntryFunc
	sync.Mutex
}
type dnsNamesToIP struct {
	nameToIP     map[string][]string
	dnsNamesLock sync.Mutex
}
type dnsttlinfo struct {
	ipaddress string
	ttl       uint32
}

type iptottlinfo struct {
	ipaddress  string
	expiryTime time.Time
	timer      *time.Timer
	contextIDs map[string]struct{}
	fqdns      map[string]struct{}
}
type serveDNS struct {
	contextID string
	*Proxy
}

const (
	dnsRequestTimeout = 2 * time.Second
)

func socketOptions(_, _ string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, constants.ProxyMarkInt); err != nil {
			zap.L().Error("dnsproxy: failed to mark connection", zap.Error(err))
		}
	})

	if err != nil {
		return err
	}

	return opErr
}

func listenUDP(ctx context.Context, network, addr string) (net.PacketConn, error) {
	var lc net.ListenConfig

	lc.Control = socketOptions

	return lc.ListenPacket(ctx, network, addr)
}

func forwardDNSReq(r *dns.Msg, ip net.IP, port uint16) ([]byte, []string, []*dnsttlinfo, error) {
	var ips []string
	var resp []byte
	var msg *dns.Msg
	var conn *dns.Conn
	var err error

	c := new(dns.Client)

	dial := func(address string) (*dns.Conn, error) {
		c.Dialer = &net.Dialer{
			Control: func(_, _ string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, constants.ProxyMarkInt); err != nil {
						zap.L().Error("dnsproxy: failed to assing mark to socket", zap.Error(err))
					}
				})
			},
			Timeout: dnsRequestTimeout,
		}

		conn, err := c.Dial(address)
		if err != nil {
			return nil, err
		}

		return conn, nil
	}

	sendRequest := func(r *dns.Msg, conn *dns.Conn) error {
		opt := r.IsEdns0()
		// If EDNS0 is used use that for size.
		if opt != nil && opt.UDPSize() >= dns.MinMsgSize {
			conn.UDPSize = opt.UDPSize()
		}
		// Otherwise use the client's configured UDP size.
		if opt == nil && c.UDPSize >= dns.MinMsgSize {
			conn.UDPSize = c.UDPSize
		}

		t := time.Now()
		// write with the appropriate write timeout
		if err = conn.SetWriteDeadline(t.Add(c.Dialer.Timeout)); err != nil {
			return err
		}

		if err = conn.WriteMsg(r); err != nil {
			return err
		}

		return nil
	}

	readResponse := func(conn *dns.Conn) ([]byte, *dns.Msg, error) {
		if err := conn.SetReadDeadline(time.Now().Add(c.Dialer.Timeout)); err != nil {
			return nil, nil, err
		}

		p, err := conn.ReadMsgHeader(nil)
		if err != nil {
			return nil, nil, err
		}

		m := new(dns.Msg)
		if err := m.Unpack(p); err != nil {
			// If an error was returned, we still want to allow the user to use
			// the message, but naively they can just check err if they don't want
			// to use an erroneous message
			return nil, nil, err
		}

		return p, m, nil
	}

	if conn, err = dial(net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))); err != nil {
		return nil, nil, nil, err
	}

	defer conn.Close() // nolint: errcheck

	if err := sendRequest(r, conn); err != nil {
		return nil, nil, nil, err
	}

	if resp, msg, err = readResponse(conn); err != nil {
		return nil, nil, nil, err
	}
	dnsttlinfolist := []*dnsttlinfo{}

	for _, ans := range msg.Answer {
		if ans.Header().Rrtype == dns.TypeA {
			t, _ := ans.(*dns.A)

			ips = append(ips, t.A.String())
			dnsttlinfolist = append(dnsttlinfolist, &dnsttlinfo{
				ipaddress: t.A.String(),
				ttl:       ans.Header().Ttl,
			})
		}

		if ans.Header().Rrtype == dns.TypeAAAA {
			t, _ := ans.(*dns.AAAA)
			ips = append(ips, t.AAAA.String())

			dnsttlinfolist = append(dnsttlinfolist, &dnsttlinfo{
				ipaddress: t.AAAA.String(),
				ttl:       ans.Header().Ttl,
			})
		}
	}
	return resp, ips, dnsttlinfolist, nil
}

const (
	strInvalidDNSRequest = "invalid DNS request"
)

func (s *serveDNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	var err error
	lAddr := w.LocalAddr().(*net.UDPAddr)
	rAddr := w.RemoteAddr().(*net.UDPAddr)
	var pctx *pucontext.PUContext
	var ipsRaw []string
	var origIP net.IP
	var origPort uint16
	var reportError string

	defer func() {
		if pctx != nil {
			// if there is no question section, this was an invalid request
			name := "invalid"
			if len(r.Question) > 0 {
				name = r.Question[0].Name
			}
			s.reportDNSLookup(name, pctx, rAddr.IP, uint16(rAddr.Port), origIP, origPort, ipsRaw, reportError)
		}
	}()

	pctxRaw, err := s.puFromID.Get(s.contextID)
	if err != nil {
		zap.L().Error("dnsproxy: context not found for the PU with ID", zap.String("contextID", s.contextID), zap.Error(err))
		reportError = fmt.Sprintf("PU context: %s", err)
		return
	}
	pctx = pctxRaw.(*pucontext.PUContext)

	// check if the DNS request is actually valid
	// we have seen with the AWS resolve in the past that it *does* respond with an empty Question section
	if len(r.Question) <= 0 {
		pctx.Counters().IncrementCounter(counters.ErrDNSInvalidRequest)
		zap.L().Debug("dnsproxy: invalid DNS request received (missing question section)", zap.String("contextID", s.contextID))
		reportError = strInvalidDNSRequest
		return
	}

	// TODO: shouldn't we let the lookup go regardless of our problems?
	origIP, origPort, _, err = s.conntrack.GetOriginalDest(net.ParseIP("127.0.0.1"), rAddr.IP, uint16(lAddr.Port), uint16(rAddr.Port), 17)
	if err != nil {
		zap.L().Error("dnsproxy: failed to find flow for the redirected DNS traffic", zap.String("contextID", s.contextID), zap.Error(err))
		reportError = fmt.Sprintf("conntrack: DNS request flow: %s", err)
		return
	}

	// perform the upstream DNS lookup
	dnsReply, ipsRaw, dnsttlinfolistRaw, err := forwardDNSReq(r, origIP, origPort)
	if err != nil {
		pctx.Counters().IncrementCounter(counters.ErrDNSForwardFailed)
		zap.L().Debug("dnsproxy: forwarded DNS request returned error", zap.String("contextID", s.contextID), zap.Error(err))
		reportError = fmt.Sprintf("DNS request failed: %s", err)
		return
	}

	// get all policies associated with the FQDN from
	policies, policyName, err1 := pctx.GetPolicyFromFQDN(r.Question[0].Name)

	// if they exist, then err1 is nil, and we need to update
	// - the ipsets
	// - the applicationacls inside of the enforcer
	// - the internal cache
	if err1 == nil {
		type ipDetail struct {
			ttl        uint32
			updateOnly bool
		}
		ipsToProcess := make(map[string]ipDetail, len(ipsRaw))
		for _, pol := range policies {
			for _, i := range dnsttlinfolistRaw {
				// TODO: this does not work yet - will come in a separate PR
				//if checkIfACLExists(pctx, pol, i.ipaddress) {
				//	// no need to program ACLs and ipsets
				//	// however, there are two cases here:
				//	// 1. this was a static entry in the external network, and we truly want to skip it
				//	// 2. this comes from us programming it down below
				//	// In case (2) we need to actually call handleTTLInfoList but with updateOnly to extend the TTL
				//	// This way no new expiry entries will be made when not necessary as for static entries,
				//	// but they will be extended when necessary as well.
				//	if _, ok := ipsToProcess[i.ipaddress]; !ok {
				//		ipsToProcess[i.ipaddress] = ipDetail{ttl: i.ttl, updateOnly: true}
				//	}
				//	continue
				//}

				if _, ok := ipsToProcess[i.ipaddress]; !ok {
					ipsToProcess[i.ipaddress] = ipDetail{ttl: i.ttl, updateOnly: false}
				}
				ips := []string{i.ipaddress}

				// makes sure to update any ipsets related to the serviceID of the policy
				// this matches the case when the destinations are *not* overlapping with the target networks and the decision is not done
				// in the enforcer
				zap.L().Debug("dnsproxy: ipset: adding IP addresses", zap.String("contextID", s.contextID), zap.String("serviceID", pol.Policy.ServiceID), zap.Strings("ipaddresses", ips))
				ipsetmanager.V4().UpdateACLIPsets(ips, pol.Policy.ServiceID)
				ipsetmanager.V6().UpdateACLIPsets(ips, pol.Policy.ServiceID)

				// makes sure to update the ApplicationACLs inside of the enforcer
				// this matches the case when the destination is overlapping with the target networks, and the decision is made inside
				// of the enforcer, and not with ipsets
				zap.L().Debug("dnsproxy: adding IP addresses to enforcer ApplicationACLs", zap.String("contextID", s.contextID), zap.String("serviceID", pol.Policy.ServiceID), zap.Strings("ipaddresses", ips))
				if err1 := pctx.UpdateApplicationACLs(policy.IPRuleList{{
					Addresses: ips,
					Ports:     pol.Ports,
					Protocols: pol.Protocols,
					Policy:    pol.Policy,
				}}); err1 != nil {
					zap.L().Error("dnsproxy: adding IP rule returned error", zap.String("contextID", s.contextID), zap.Error(err1))
				}
			}
		}

		// for processing in our caches, we only care about the IPs that we needed to program ACLs/ipsets
		ips := make([]string, 0, len(ipsToProcess))
		var dnsttlinfolist, dnsttlinfolistUpdateOnly []*dnsttlinfo
		for ip, d := range ipsToProcess {
			if d.updateOnly {
				dnsttlinfolistUpdateOnly = append(dnsttlinfolistUpdateOnly, &dnsttlinfo{ipaddress: ip, ttl: d.ttl})
			} else {
				ips = append(ips, ip)
				dnsttlinfolist = append(dnsttlinfolist, &dnsttlinfo{ipaddress: ip, ttl: d.ttl})
			}
		}

		// update the cache/map for this FQDN with new
		s.updateFQDNWithIPs(s.contextID, policyName, ips)

		// add or update only if required the expiry entries
		s.handleTTLInfoList(s.contextID, policyName, dnsttlinfolist, false)
		s.handleTTLInfoList(s.contextID, policyName, dnsttlinfolistUpdateOnly, true)
	}

	configureDependentServices(pctx, r.Question[0].Name, ipsRaw)

	// write the DNS reply back to the client
	if _, err = w.Write(dnsReply); err != nil {
		pctx.Counters().IncrementCounter(counters.ErrDNSResponseFailed)
		zap.L().Error("dnsproxy: writing DNS response back to the client returned error", zap.String("contextID", s.contextID), zap.Error(err))
	}
}

// TODO: this does not work yet - will come in a separate PR
// func checkIfACLExists(pctx *pucontext.PUContext, pol policy.PortProtocolPolicy, ipStr string) bool {
// 	ip := net.ParseIP(ipStr)
// 	if ip == nil {
// 		return false
// 	}
// 	for _, protoStr := range pol.Protocols {
// 		proto, err := strconv.Atoi(protoStr)
// 		if err != nil {
// 			continue
// 		}
// 		for _, portStr := range pol.Ports {
// 			// it could be a range definition
// 			var ports []uint16
// 			if strings.Contains(portStr, ":") {
// 				tmp := strings.SplitN(portStr, ":", 2)
// 				if len(tmp) != 2 {
// 					continue
// 				}
// 				startPort, err := strconv.Atoi(tmp[0])
// 				if err != nil {
// 					continue
// 				}
// 				endPort, err := strconv.Atoi(tmp[1])
// 				if err != nil {
// 					continue
// 				}
// 				ports = make([]uint16, 0, endPort-startPort+1)
// 				for i := startPort; i <= endPort; i++ {
// 					ports = append(ports, uint16(i))
// 				}
// 			} else {
// 				port, err := strconv.Atoi(portStr)
// 				if err != nil {
// 					continue
// 				}
// 				ports = []uint16{uint16(port)}
// 			}

// 			for _, port := range ports {
// 				reportPol, actionPol, err := pctx.ApplicationACLPolicyFromAddr(ip, port, uint8(proto))
// 				if err == nil && (reportPol != nil || actionPol != nil) {
// 					zap.L().Debug("dnsproxy: ACL already found for IP",
// 						zap.String("contextID", pctx.ManagementID()),
// 						zap.String("ipaddress", ipStr),
// 						zap.Any("reportPol", reportPol),
// 						zap.Any("actionPol", actionPol),
// 					)
// 					return true
// 				}
// 			}
// 		}
// 	}
// 	return false
// }

func (p *Proxy) handleTTLInfoList(contextID, fqdn string, dnsttlinfolist []*dnsttlinfo, updateOnly bool) {
	for _, dnsinfo := range dnsttlinfolist {
		zap.L().Debug("handleTTLInfoList", zap.String("fqdn", fqdn), zap.String("ipaddress", dnsinfo.ipaddress), zap.Bool("updateOnly", updateOnly))
		p.handleTTLInfo(contextID, fqdn, dnsinfo, updateOnly)
	}
}

func (p *Proxy) handleTTLInfo(contextID, fqdn string, dnsinfo *dnsttlinfo, updateOnly bool) {
	newEntryExpiryTime := time.Now().Add(time.Duration(dnsinfo.ttl) * time.Second)
	ul := p.IPToTTLLocks.Lock(dnsinfo.ipaddress)
	defer ul.Unlock()
	ttlInfoRaw, err := p.IPToTTL.Get(dnsinfo.ipaddress)
	if err != nil {
		// if we are supposed to be updating only
		// then skip this entry
		if updateOnly {
			return
		}

		// otherwise add a new entry
		newEntry := iptottlinfo{
			ipaddress:  dnsinfo.ipaddress,
			expiryTime: newEntryExpiryTime,
			contextIDs: map[string]struct{}{contextID: {}},
			fqdns:      map[string]struct{}{fqdn: {}},
		}
		// NOTE: the dnsinfo.ipaddress is in a for loop
		// so we need to make sure the IP address is on the stack when the callback is called
		// hence the anonymous function wrapping of the timer
		func(ipaddress string) {
			newEntry.timer = time.AfterFunc(time.Duration(dnsinfo.ttl)*time.Second, func() {
				if p.removeExpiredEntry != nil {
					p.removeExpiredEntry(ipaddress)
				}
			})
		}(dnsinfo.ipaddress)
		if err := p.IPToTTL.Add(dnsinfo.ipaddress, newEntry); err != nil {
			zap.L().Debug("dnsproxy: failed to add entry to IPToTTL cache", zap.String("contextID", contextID), zap.Any("iptottlinfo", newEntry), zap.Error(err))
			return
		}
	} else {
		// update TTL info and reset timer if necessary
		ttlInfo := ttlInfoRaw.(iptottlinfo)
		if newEntryExpiryTime.After(ttlInfo.expiryTime) {
			ttlInfo.timer.Reset(time.Duration(dnsinfo.ttl) * time.Second)
		}
		ttlInfo.expiryTime = newEntryExpiryTime
		ttlInfo.contextIDs[contextID] = struct{}{}
		ttlInfo.fqdns[fqdn] = struct{}{}
		p.IPToTTL.AddOrUpdate(dnsinfo.ipaddress, ttlInfo)
	}
}

func (p *Proxy) defaultRemoveExpiredEntry(ipaddress string) {
	// retrieve the IPtoTTLInfo
	ul := p.IPToTTLLocks.Lock(ipaddress)
	defer ul.Unlock()
	ttlInfoRaw, err := p.IPToTTL.Get(ipaddress)
	if err != nil {
		zap.L().Debug("dnsproxy: entry already gone from IPToTTL cache", zap.String("ipaddress", ipaddress))
		return
	}
	ttlInfo := ttlInfoRaw.(iptottlinfo)

	for contextID := range ttlInfo.contextIDs {
		pctxRaw, err := p.puFromID.Get(contextID)
		if err != nil {
			zap.L().Error("dnsproxy: context not found for the PU with ID", zap.String("contextID", contextID))
			continue
		}
		pctx := pctxRaw.(*pucontext.PUContext)

		for fqdn := range ttlInfo.fqdns {
			policies, policyName, err := pctx.GetPolicyFromFQDN(fqdn)
			if err != nil {
				continue
			}

			// remove IP address from ipsets
			for _, pol := range policies {
				zap.L().Debug("dnsproxy: ipset: removing IP address", zap.String("contextID", contextID), zap.String("serviceID", pol.Policy.ServiceID), zap.String("ipaddress", ipaddress))
				ipsetmanager.V4().DeleteEntryFromIPset([]string{ipaddress}, pol.Policy.ServiceID)
				ipsetmanager.V6().DeleteEntryFromIPset([]string{ipaddress}, pol.Policy.ServiceID)

				// remove IP address from enforcer ApplicationACLs
				zap.L().Debug("dnsproxy: removing IP address from enforcer ApplicationACL", zap.String("contextID", contextID), zap.String("ipaddress", ipaddress))
				if err := pctx.RemoveApplicationACL(ipaddress, pol.Protocols, pol.Ports, pol.Policy); err != nil {
					zap.L().Debug("dnsproxy: RemoveApplicationACL failed", zap.String("contextID", contextID), zap.String("serviceID", pol.Policy.ServiceID), zap.String("ipaddress", ipaddress), zap.Error(err))
				}
			}

			p.removeIPfromFQDN(contextID, policyName, ipaddress)
		}
	}

	// clean up after ourselves and remove ourselves from the cache
	if err := p.IPToTTL.Remove(ipaddress); err != nil {
		zap.L().Debug("dnsproxy: failed to remove entry from IPToTTL cache", zap.String("ipaddress", ipaddress), zap.Error(err))
	}
	p.IPToTTLLocks.Remove(ipaddress)

}

// StartDNSServer starts the dns server on the port provided for contextID
func (p *Proxy) StartDNSServer(ctx context.Context, contextID, port string) error {
	netPacketConn, err := listenUDP(ctx, "udp", "127.0.0.1:"+port)
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
			zap.L().Error("dnsproxy: could not start DNS proxy server", zap.String("contextID", contextID), zap.Error(err))
		}
	}()

	return nil
}

// shutdownDNS shuts down the dns server for contextID
func (p *Proxy) shutdownDNS(contextID string) {

	if s, ok := p.contextIDToServer[contextID]; ok {
		if err := s.Shutdown(); err != nil {
			zap.L().Error("dnsproxy: shutdown of DNS server returned error", zap.String("contextID", contextID), zap.Error(err))
		}
		delete(p.contextIDToServer, contextID)
	}
}

// New creates an instance of the dns proxy
func New(ctx context.Context, puFromID cache.DataStore, conntrack flowtracking.FlowClient, c collector.EventCollector) *Proxy {
	ch := make(chan dnsReport)
	p := &Proxy{
		chreports:                ch,
		puFromID:                 puFromID,
		collector:                c,
		conntrack:                conntrack,
		contextIDToServer:        map[string]*dns.Server{},
		contextIDToDNSNames:      cache.NewCache("contextIDtoDNSNames"),
		contextIDToDNSNamesLocks: newMutexMap(),
		IPToTTL:                  cache.NewCache("IPToTTL"),
		IPToTTLLocks:             newMutexMap(),
	}
	p.removeExpiredEntry = p.defaultRemoveExpiredEntry
	go p.reportDNSRequests(ctx, ch)
	return p
}

// SyncWithPlatformCache is only needed in Windows currently
func (p *Proxy) SyncWithPlatformCache(ctx context.Context, pctx *pucontext.PUContext) error {
	return nil
}

// HandleDNSResponsePacket is only needed in Windows currently
func (p *Proxy) HandleDNSResponsePacket(dnsPacketData []byte, sourceIP net.IP, sourcePort uint16, destIP net.IP, destPort uint16, puFromContextID func(string) (*pucontext.PUContext, error)) error {
	return nil
}

// Enforce starts enforcing policies for the given policy.PUInfo.
func (p *Proxy) Enforce(ctx context.Context, contextID string, puInfo *policy.PUInfo) error {
	// during the first Enforce call, we still need to initialize map
	// we do that and return
	ul := p.contextIDToDNSNamesLocks.Lock(contextID)
	defer ul.Unlock()
	tmp, err := p.contextIDToDNSNames.Get(contextID)
	if err != nil {
		// this means that the map is not initialized yet, do so now
		return p.doHandleCreate(ctx, contextID, puInfo)
	}

	// during a policy refresh, we will enter this part here:
	// - iterate over all DNSACLs for this PU
	// - for all already learned IPs for all DNS names: program ipsets and enforcer ApplicationACLs
	dnsNames := tmp.(*dnsNamesToIP).Copy()
	for fqdn, policies := range puInfo.Policy.DNSACLs {
		ips, ok := dnsNames.nameToIP[fqdn]
		if ok {
			// we have already learned those DNS names
			// make sure to reprogram ipsets and ApplicationACLs in the enforcer
			// on a policy refresh
			for _, pol := range policies {
				zap.L().Debug("dnsproxy: ipset: adding IP addresses after policy refresh", zap.String("contextID", contextID), zap.String("fqdn", fqdn), zap.String("serviceID", pol.Policy.ServiceID), zap.Strings("ipaddresses", ips))
				ipsetmanager.V4().UpdateACLIPsets(ips, pol.Policy.ServiceID)
				ipsetmanager.V6().UpdateACLIPsets(ips, pol.Policy.ServiceID)

				// makes sure to update the ApplicationACLs inside of the enforcer
				// this matches the case when the destination is overlapping with the target networks, and the decision is made inside
				// of the enforcer, and not with ipsets
				data, err := p.puFromID.Get(contextID)
				if err != nil {
					zap.L().Error("dnsproxy: context not found for the PU with ID", zap.String("contextID", contextID))
					continue
				}
				pctx := data.(*pucontext.PUContext)
				if err1 := pctx.UpdateApplicationACLs(policy.IPRuleList{{
					Addresses: ips,
					Ports:     pol.Ports,
					Protocols: pol.Protocols,
					Policy:    pol.Policy,
				}}); err1 != nil {
					zap.L().Error("dnsproxy: adding IP rule returned error after policy refresh", zap.String("contextID", contextID), zap.Error(err1))
				}
			}
			continue
		}
		// This is a new fqdn. DNS proxy will fix these IPs as it learns them
		dnsNames.nameToIP[fqdn] = []string{}
	}
	// this is only necessary to add new FQDNs to the map - which is essential for the DNS proxy to know about
	p.contextIDToDNSNames.AddOrUpdate(contextID, dnsNames)
	return nil
}

func (p *Proxy) doHandleCreate(_ context.Context, contextID string, puInfo *policy.PUInfo) error {
	nameToIP := &dnsNamesToIP{
		nameToIP: map[string][]string{},
	}
	for name := range puInfo.Policy.DNSACLs {
		nameToIP.nameToIP[name] = []string{}
	}
	if err := p.contextIDToDNSNames.Add(contextID, nameToIP); err != nil {
		zap.L().Error("dnsproxy: contextID already enforced", zap.String("contextID", contextID))
	}

	return nil
}

// Unenforce stops enforcing policy for the given IP.
func (p *Proxy) Unenforce(_ context.Context, contextID string) error {
	p.Lock()
	defer p.Unlock()
	ul := p.contextIDToDNSNamesLocks.Lock(contextID)
	if err := p.contextIDToDNSNames.Remove(contextID); err != nil {
		zap.L().Error("dnsproxy: contextID already removed/unenforced", zap.String("contextID", contextID))
	}
	p.contextIDToDNSNamesLocks.Remove(contextID)
	ul.Unlock()
	p.shutdownDNS(contextID)
	return nil
}

func (d *dnsNamesToIP) Copy() *dnsNamesToIP {
	d.dnsNamesLock.Lock()
	defer d.dnsNamesLock.Unlock()
	newdns := &dnsNamesToIP{
		nameToIP: make(map[string][]string, len(d.nameToIP)),
	}
	for key, value := range d.nameToIP {
		newvalue := make([]string, len(value))
		copy(newvalue, value)
		newdns.nameToIP[key] = newvalue
	}

	return newdns
}

// updateFQDNWithIPs will add any new IPs in `ips` and add it to the internal map of `contextIDToDNSNames` for our s.contextID
func (p *Proxy) updateFQDNWithIPs(contextID, fqdn string, ips []string) {
	ul := p.contextIDToDNSNamesLocks.Lock(contextID)
	defer ul.Unlock()
	tmp, err := p.contextIDToDNSNames.Get(contextID)
	if err != nil {
		zap.L().Debug("dnsproxy: failed to get fqdn map for contextID in updateFQDNWithIPs", zap.String("contextID", contextID))
		return
	}
	fqdntoIPs := tmp.(*dnsNamesToIP).Copy()
	existingIPsMap := make(map[string]struct{}, len(fqdntoIPs.nameToIP[fqdn]))
	for _, e := range fqdntoIPs.nameToIP[fqdn] {
		existingIPsMap[e] = struct{}{}
	}
	toAdd := make([]string, 0, len(ips))
	for _, newIP := range ips {
		if _, ok := existingIPsMap[newIP]; ok {
			continue
		}
		toAdd = append(toAdd, newIP)
	}
	fqdntoIPs.nameToIP[fqdn] = append(fqdntoIPs.nameToIP[fqdn], toAdd...)
	_ = p.contextIDToDNSNames.AddOrUpdate(contextID, fqdntoIPs)
	zap.L().Debug("dnsproxy: updating FQDN map after IP addresses were added", zap.String("contextID", contextID), zap.Any("fqdntoIPs", fqdntoIPs.nameToIP))
}

func (p *Proxy) removeIPfromFQDN(contextID, fqdn string, ipAddress string) {
	ul := p.contextIDToDNSNamesLocks.Lock(contextID)
	defer ul.Unlock()
	tmp, err := p.contextIDToDNSNames.Get(contextID)
	if err != nil {
		zap.L().Debug("dnsproxy: failed to get fqdn map for contextID in removeIPfromFQDN", zap.String("contextID", contextID))
		return
	}
	fqdntoIPs := tmp.(*dnsNamesToIP).Copy()
	existingIPsMap := make(map[string]struct{}, len(fqdntoIPs.nameToIP[fqdn]))
	for _, e := range fqdntoIPs.nameToIP[fqdn] {
		existingIPsMap[e] = struct{}{}
	}

	// remove IP from map/cache
	if len(fqdntoIPs.nameToIP[fqdn]) > 0 {
		ips := make([]string, 0, len(fqdntoIPs.nameToIP[fqdn])-1)
		var found bool
		for _, ip := range fqdntoIPs.nameToIP[fqdn] {
			if ip == ipAddress {
				found = true
				continue
			}
			ips = append(ips, ip)
		}
		if !found {
			zap.L().Debug("dnsproxy: ipaddress was already removed from list", zap.String("contextID", contextID), zap.String("fqdn", fqdn), zap.String("ipaddress", ipAddress))
		}
		fqdntoIPs.nameToIP[fqdn] = ips
	}

	zap.L().Debug("dnsproxy: updating FQDN map after IP address was deleted", zap.String("contextID", contextID), zap.Any("iplist", fqdntoIPs.nameToIP))
	_ = p.contextIDToDNSNames.AddOrUpdate(contextID, fqdntoIPs) // nolint
}
