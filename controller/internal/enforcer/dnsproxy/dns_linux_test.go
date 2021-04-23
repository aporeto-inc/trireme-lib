// +build linux

package dnsproxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/magiconair/properties/assert"
	"github.com/miekg/dns"
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/acls"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cache"
)

type flowClientDummy struct {
}

func (c *flowClientDummy) Close() error {
	return nil
}

func (c *flowClientDummy) UpdateMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32, network bool) error {
	return nil
}

func (c *flowClientDummy) UpdateNetworkFlowMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32) error {
	return nil
}

func (c *flowClientDummy) UpdateApplicationFlowMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32) error {
	return nil
}

func findDNSServerIP() net.IP {

	file, err := os.Open("/etc/resolv.conf")

	if err != nil {
		return net.ParseIP("8.8.8.8")
	}

	scanner := bufio.NewScanner(file)

	// this regex is doing a whole word search
	s := "\\b" + "nameserver" + "\\b"
	match := regexp.MustCompile(s)

	for scanner.Scan() {
		line := scanner.Text()
		if match.MatchString(line) {
			return net.ParseIP(strings.Fields(line)[1])
		}
	}

	return net.ParseIP("8.8.8.8")
}

func (c *flowClientDummy) GetOriginalDest(ipSrc, ipDst net.IP, srcport, dstport uint16, protonum uint8) (net.IP, uint16, uint32, error) {

	dnsServerIP := findDNSServerIP()
	fmt.Println("using DNS Server IP", dnsServerIP)
	return dnsServerIP, 53, 100, nil
}

func addDNSNamePolicy(context *pucontext.PUContext) {
	context.DNSACLs = policy.DNSRuleList{
		"www.google.com.": []policy.PortProtocolPolicy{
			{Ports: []string{"80"},
				Protocols: []string{"tcp"},
				Policy: &policy.FlowPolicy{
					Action:   policy.Accept,
					PolicyID: "2",
				}},
		},
	}
}

func CustomDialer(ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{}
	return d.DialContext(ctx, "udp", "127.0.0.1:53001")
}

func createCustomResolver() *net.Resolver {
	r := &net.Resolver{
		PreferGo: true,
		Dial:     CustomDialer,
	}

	return r
}

// DNSCollector implements a default collector infrastructure to syslog
type DNSCollector struct{}

// CollectFlowEvent is part of the EventCollector interface.
func (d *DNSCollector) CollectFlowEvent(record *collector.FlowRecord) {}

// CollectContainerEvent is part of the EventCollector interface.
func (d *DNSCollector) CollectContainerEvent(record *collector.ContainerRecord) {}

// CollectUserEvent is part of the EventCollector interface.
func (d *DNSCollector) CollectUserEvent(record *collector.UserRecord) {}

// CollectTraceEvent collects iptables trace events
func (d *DNSCollector) CollectTraceEvent(records []string) {}

// CollectPingEvent collects ping events
func (d *DNSCollector) CollectPingEvent(report *collector.PingReport) {}

// CollectPacketEvent collects packet events from the datapath
func (d *DNSCollector) CollectPacketEvent(report *collector.PacketReport) {}

// CollectCounterEvent collect counters from the datapath
func (d *DNSCollector) CollectCounterEvent(report *collector.CounterReport) {}

// CollectConnectionExceptionReport collects the connection exception report
func (d *DNSCollector) CollectConnectionExceptionReport(_ *collector.ConnectionExceptionReport) {
}

var r collector.DNSRequestReport
var l sync.Mutex

// CollectDNSRequests collect counters from the datapath
func (d *DNSCollector) CollectDNSRequests(report *collector.DNSRequestReport) {
	l.Lock()
	r = *report
	l.Unlock()
}

func TestDNS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	puIDcache := cache.NewCache("puFromContextID")

	fp := &policy.PUInfo{
		Runtime: policy.NewPURuntimeWithDefaults(),
		Policy:  policy.NewPUPolicyWithDefaults(),
	}
	pu, _ := pucontext.NewPU("pu1", fp, nil, 24*time.Hour) // nolint

	addDNSNamePolicy(pu)

	puIDcache.AddOrUpdate("pu1", pu)
	conntrack := &flowClientDummy{}
	collector := &DNSCollector{}

	proxy := New(ctx, puIDcache, conntrack, collector)

	err := proxy.StartDNSServer(ctx, "pu1", "53001")
	assert.Equal(t, err == nil, true, "start dns server")

	resolver := createCustomResolver()
	waitTimeBeforeReport = 3 * time.Second
	resolver.LookupIPAddr(ctx, "www.google.com") // nolint
	resolver.LookupIPAddr(ctx, "www.google.com") // nolint

	assert.Equal(t, err == nil, true, "err should be nil")

	time.Sleep(5 * time.Second)
	l.Lock()
	assert.Equal(t, r.NameLookup == "www.google.com.", true, "lookup should be www.google.com")
	assert.Equal(t, r.Count >= 2 && r.Count <= 10, true, fmt.Sprintf("count should be 2, got %d", r.Count))
	l.Unlock()
	proxy.Unenforce(ctx, "pu1") // nolint
}

const (
	contextID   = "host"
	serviceID   = "serviceID"
	port80      = "80"
	fqdn        = "www.example.com."
	fqdnTwo     = "two.example.com."
	fqdnKeep    = "keep.example.com."
	ip192_0_2_1 = "192.0.2.1"
	ip192_0_2_2 = "192.0.2.2"
	ip192_0_2_3 = "192.0.2.3"
)

func TestProxy_removeIPfromFQDN(t *testing.T) {
	type args struct {
		contextID string
		fqdn      string
		ipAddress string
	}
	tests := []struct {
		name             string
		args             args
		existing         map[string]*dnsNamesToIP
		wantContextEntry bool
		want             map[string][]string
	}{
		{
			name: "context not in cache",
			args: args{
				contextID: "does not exist",
				fqdn:      fqdn,
				ipAddress: "",
			},
			wantContextEntry: false,
		},
		{
			name: "nothing to remove from empty list",
			args: args{
				contextID: contextID,
				fqdn:      fqdn,
				ipAddress: ip192_0_2_1,
			},
			wantContextEntry: true,
			existing: map[string]*dnsNamesToIP{
				contextID: {
					nameToIP: map[string][]string{
						fqdnKeep: {ip192_0_2_1},
						fqdn:     {},
					},
				},
			},
			want: map[string][]string{
				fqdnKeep: {ip192_0_2_1},
				fqdn:     {},
			},
		},
		{
			name: "IP does not match from existing list",
			args: args{
				contextID: contextID,
				fqdn:      fqdn,
				ipAddress: ip192_0_2_1,
			},
			wantContextEntry: true,
			existing: map[string]*dnsNamesToIP{
				contextID: {
					nameToIP: map[string][]string{
						fqdnKeep: {ip192_0_2_1},
						fqdn:     {ip192_0_2_2},
					},
				},
			},
			want: map[string][]string{
				fqdnKeep: {ip192_0_2_1},
				fqdn:     {ip192_0_2_2},
			},
		},
		{
			name: "IP successfully being removed from list",
			args: args{
				contextID: contextID,
				fqdn:      fqdn,
				ipAddress: ip192_0_2_1,
			},
			wantContextEntry: true,
			existing: map[string]*dnsNamesToIP{
				contextID: {
					nameToIP: map[string][]string{
						fqdnKeep: {ip192_0_2_1},
						fqdn:     {ip192_0_2_1},
					},
				},
			},
			want: map[string][]string{
				fqdnKeep: {ip192_0_2_1},
				fqdn:     {},
			},
		},
		{
			name: "IP successfully being removed from list with other entries",
			args: args{
				contextID: contextID,
				fqdn:      fqdn,
				ipAddress: ip192_0_2_2,
			},
			wantContextEntry: true,
			existing: map[string]*dnsNamesToIP{
				contextID: {
					nameToIP: map[string][]string{
						fqdnKeep: {ip192_0_2_1},
						fqdn:     {ip192_0_2_1, ip192_0_2_2, ip192_0_2_3},
					},
				},
			},
			want: map[string][]string{
				fqdnKeep: {ip192_0_2_1},
				fqdn:     {ip192_0_2_1, ip192_0_2_3},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{
				contextIDToDNSNames:      cache.NewCache("contextIDtoDNSNames"),
				contextIDToDNSNamesLocks: newMutexMap(),
			}
			for k, v := range tt.existing {
				p.contextIDToDNSNames.AddOrUpdate(k, v)
			}
			p.removeIPfromFQDN(tt.args.contextID, tt.args.fqdn, tt.args.ipAddress)

			val, err := p.contextIDToDNSNames.Get(tt.args.contextID)
			if (err == nil) != tt.wantContextEntry {
				t.Errorf("entry for context %q does not exist", tt.args.contextID)
			}
			if err == nil {
				m := val.(*dnsNamesToIP)
				if !reflect.DeepEqual(m.nameToIP, tt.want) {
					t.Errorf("want %#v, have %#v", tt.want, m.nameToIP)
				}
			}
		})
	}
}

func TestProxy_updateFQDNWithIPs(t *testing.T) {
	type args struct {
		contextID   string
		fqdn        string
		ipAddresses []string
	}
	tests := []struct {
		name             string
		args             args
		existing         map[string]*dnsNamesToIP
		wantContextEntry bool
		want             map[string][]string
	}{
		{
			name: "context not in cache",
			args: args{
				contextID:   "does not exist",
				fqdn:        fqdn,
				ipAddresses: nil,
			},
			wantContextEntry: false,
		},
		{
			name: "adding an empty list",
			args: args{
				contextID:   contextID,
				fqdn:        fqdn,
				ipAddresses: []string{},
			},
			wantContextEntry: true,
			existing: map[string]*dnsNamesToIP{
				contextID: {
					nameToIP: map[string][]string{
						fqdnKeep: {ip192_0_2_1},
						fqdn:     {},
					},
				},
			},
			want: map[string][]string{
				fqdnKeep: {ip192_0_2_1},
				fqdn:     {},
			},
		},
		{
			name: "adding IPs to an empty list",
			args: args{
				contextID:   contextID,
				fqdn:        fqdn,
				ipAddresses: []string{ip192_0_2_2, ip192_0_2_3},
			},
			wantContextEntry: true,
			existing: map[string]*dnsNamesToIP{
				contextID: {
					nameToIP: map[string][]string{
						fqdnKeep: {ip192_0_2_1},
						fqdn:     {},
					},
				},
			},
			want: map[string][]string{
				fqdnKeep: {ip192_0_2_1},
				fqdn:     {ip192_0_2_2, ip192_0_2_3},
			},
		},
		{
			name: "adding an existing IP to the list",
			args: args{
				contextID:   contextID,
				fqdn:        fqdn,
				ipAddresses: []string{ip192_0_2_2},
			},
			wantContextEntry: true,
			existing: map[string]*dnsNamesToIP{
				contextID: {
					nameToIP: map[string][]string{
						fqdnKeep: {ip192_0_2_1},
						fqdn:     {ip192_0_2_1, ip192_0_2_2},
					},
				},
			},
			want: map[string][]string{
				fqdnKeep: {ip192_0_2_1},
				fqdn:     {ip192_0_2_1, ip192_0_2_2},
			},
		},
		{
			name: "adding an existing IP and a new IP to an existing list",
			args: args{
				contextID:   contextID,
				fqdn:        fqdn,
				ipAddresses: []string{ip192_0_2_2, ip192_0_2_3},
			},
			wantContextEntry: true,
			existing: map[string]*dnsNamesToIP{
				contextID: {
					nameToIP: map[string][]string{
						fqdnKeep: {ip192_0_2_1},
						fqdn:     {ip192_0_2_1, ip192_0_2_2},
					},
				},
			},
			want: map[string][]string{
				fqdnKeep: {ip192_0_2_1},
				fqdn:     {ip192_0_2_1, ip192_0_2_2, ip192_0_2_3},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{
				contextIDToDNSNames:      cache.NewCache("contextIDtoDNSNames"),
				contextIDToDNSNamesLocks: newMutexMap(),
			}
			for k, v := range tt.existing {
				p.contextIDToDNSNames.AddOrUpdate(k, v)
			}
			p.updateFQDNWithIPs(tt.args.contextID, tt.args.fqdn, tt.args.ipAddresses)

			val, err := p.contextIDToDNSNames.Get(tt.args.contextID)
			if (err == nil) != tt.wantContextEntry {
				t.Errorf("entry for context %q does not exist", tt.args.contextID)
			}
			if err == nil {
				m := val.(*dnsNamesToIP)
				if !reflect.DeepEqual(m.nameToIP, tt.want) {
					t.Errorf("want %#v, have %#v", tt.want, m.nameToIP)
				}
			}
		})
	}
}

func TestProxy_defaultRemoveExpiredEntry(t *testing.T) {
	type args struct {
		ipaddress string
	}
	type existing struct {
		pus   map[string]*pucontext.PUContext
		fqdns map[string]*dnsNamesToIP
		ips   map[string]iptottlinfo
	}
	type want struct {
		removedFromIPToTTL bool
		fqdns              map[string]*dnsNamesToIP
	}
	tests := []struct {
		name     string
		args     args
		existing existing
		want     want
	}{
		{
			name: "TTL info for IP does not exist in cache",
			args: args{ipaddress: ip192_0_2_1},
			existing: existing{
				ips: map[string]iptottlinfo{
					ip192_0_2_2: {
						contextIDs: map[string]struct{}{
							contextID: {},
						},
						fqdns: map[string]struct{}{
							fqdn:    {},
							fqdnTwo: {},
						},
					},
				},
				fqdns: map[string]*dnsNamesToIP{
					contextID: {
						nameToIP: map[string][]string{},
					},
				},
			},
			want: want{
				removedFromIPToTTL: true,
				fqdns: map[string]*dnsNamesToIP{
					contextID: {
						nameToIP: map[string][]string{},
					},
				},
			},
		},
		{
			name: "PUContext in TTL info for IP does not exist in cache",
			args: args{ipaddress: ip192_0_2_1},
			existing: existing{
				ips: map[string]iptottlinfo{
					ip192_0_2_1: {
						contextIDs: map[string]struct{}{
							contextID: {},
						},
						fqdns: map[string]struct{}{
							fqdn:    {},
							fqdnTwo: {},
						},
					},
				},
				fqdns: map[string]*dnsNamesToIP{
					contextID: {
						nameToIP: map[string][]string{},
					},
				},
				pus: map[string]*pucontext.PUContext{},
			},
			want: want{
				removedFromIPToTTL: true,
				fqdns: map[string]*dnsNamesToIP{
					contextID: {
						nameToIP: map[string][]string{},
					},
				},
			},
		},
		{
			name: "successfully remove 192_0_2_1",
			args: args{ipaddress: ip192_0_2_1},
			existing: existing{
				pus: map[string]*pucontext.PUContext{
					contextID: {
						RWMutex:         sync.RWMutex{},
						ApplicationACLs: acls.NewACLCache(),
						DNSACLs: map[string][]policy.PortProtocolPolicy{
							fqdn: {
								{
									Ports:     []string{port80},
									Protocols: []string{constants.TCPProtoNum},
									Policy: &policy.FlowPolicy{
										ServiceID: serviceID,
									},
								},
							},
						},
					},
				},
				fqdns: map[string]*dnsNamesToIP{
					contextID: {
						nameToIP: map[string][]string{
							fqdn: {ip192_0_2_1, ip192_0_2_2},
						},
					},
				},
				ips: map[string]iptottlinfo{
					ip192_0_2_1: {
						contextIDs: map[string]struct{}{
							contextID: {},
						},
						fqdns: map[string]struct{}{
							fqdn:    {},
							fqdnTwo: {},
						},
					},
				},
			},
			want: want{
				removedFromIPToTTL: true,
				fqdns: map[string]*dnsNamesToIP{
					contextID: {
						nameToIP: map[string][]string{
							fqdn: {ip192_0_2_2},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{
				puFromID:                 cache.NewCache("puFromContextID"),
				contextIDToServer:        map[string]*dns.Server{},
				contextIDToDNSNames:      cache.NewCache("contextIDtoDNSNames"),
				contextIDToDNSNamesLocks: newMutexMap(),
				IPToTTL:                  cache.NewCache("IPToTTL"),
				IPToTTLLocks:             newMutexMap(),
			}
			for k, v := range tt.existing.pus {
				p.puFromID.AddOrUpdate(k, v)
			}
			for k, v := range tt.existing.fqdns {
				p.contextIDToDNSNames.AddOrUpdate(k, v)
			}
			for k, v := range tt.existing.ips {
				p.IPToTTL.AddOrUpdate(k, v)
			}
			p.defaultRemoveExpiredEntry(tt.args.ipaddress)

			// we check to see if the entries got removed correctly
			if _, err := p.IPToTTL.Get(tt.args.ipaddress); (err != nil) != tt.want.removedFromIPToTTL {
				t.Errorf("entry exists in IPToTTL cache: %v, want.removedFromIPToTTL %v", (err != nil), tt.want.removedFromIPToTTL)
			}
			for contextID, wantFqdns := range tt.want.fqdns {
				existingFqdnsRaw, err := p.contextIDToDNSNames.Get(contextID)
				if err != nil {
					t.Errorf("no map for context %q in contextIDToDNSNames any longer", contextID)
				}
				existingFqdns := existingFqdnsRaw.(*dnsNamesToIP)
				if !reflect.DeepEqual(wantFqdns.nameToIP, existingFqdns.nameToIP) {
					t.Errorf("context %q: have fqdns %#v - want fqdns %#v", contextID, existingFqdns.nameToIP, wantFqdns.nameToIP)
				}
			}
		})
	}
}

func TestProxy_handleTTLInfoList(t *testing.T) {
	type args struct {
		contextID      string
		fqdn           string
		dnsttlinfolist []*dnsttlinfo
		updateOnly     bool
	}
	type existing struct {
		ips map[string]iptottlinfo
	}
	type want struct {
		mustFireExpiry               bool
		newEntry                     bool
		existingEntryIncreasedExpiry bool
	}
	tests := []struct {
		name     string
		args     args
		existing existing
		want     want
	}{
		{
			name: "creating new TTL info in the cache for new IP when updateOnly is false",
			args: args{
				contextID: contextID,
				fqdn:      fqdn,
				dnsttlinfolist: []*dnsttlinfo{
					{
						ipaddress: ip192_0_2_1,
						ttl:       1,
					},
				},
				updateOnly: false,
			},
			existing: existing{
				ips: map[string]iptottlinfo{},
			},
			want: want{
				mustFireExpiry: true,
				newEntry:       true,
			},
		},
		{
			name: "not creating new TTL info in the cache for new IP when updateOnly is true",
			args: args{
				contextID: contextID,
				fqdn:      fqdn,
				dnsttlinfolist: []*dnsttlinfo{
					{
						ipaddress: ip192_0_2_1,
						ttl:       1,
					},
				},
				updateOnly: true,
			},
			existing: existing{
				ips: map[string]iptottlinfo{},
			},
			want: want{
				mustFireExpiry: false,
				newEntry:       false,
			},
		},
		{
			name: "updating existing TTL info in the cache",
			args: args{
				contextID: contextID,
				fqdn:      fqdn,
				dnsttlinfolist: []*dnsttlinfo{
					{
						ipaddress: ip192_0_2_1,
						ttl:       1,
					},
				},
				updateOnly: true,
			},
			existing: existing{
				ips: map[string]iptottlinfo{
					ip192_0_2_1: {
						ipaddress:  ip192_0_2_1,
						expiryTime: time.Now(),
						contextIDs: map[string]struct{}{},
						fqdns:      map[string]struct{}{},
					},
				},
			},
			want: want{
				mustFireExpiry:               true,
				existingEntryIncreasedExpiry: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{
				puFromID:                 cache.NewCache("puFromContextID"),
				contextIDToServer:        map[string]*dns.Server{},
				contextIDToDNSNames:      cache.NewCache("contextIDtoDNSNames"),
				contextIDToDNSNamesLocks: newMutexMap(),
				IPToTTL:                  cache.NewCache("IPToTTL"),
				IPToTTLLocks:             newMutexMap(),
			}

			// exercises the expiry trigger
			var wg sync.WaitGroup
			if tt.want.mustFireExpiry {
				wg.Add(1)
			}
			p.removeExpiredEntry = func(ipaddress string) {
				// this is just to exercise the expiry trigger
				t.Logf("removeExpiredEntry %q", ipaddress)
				wg.Done()
			}

			for k, v := range tt.existing.ips {
				// TODO: this is awful, not sure how to better mock this at this point
				v.timer = time.AfterFunc(time.Second, func() {
					if p.removeExpiredEntry != nil {
						p.removeExpiredEntry(k)
					}
				})
				p.IPToTTL.AddOrUpdate(k, v)
			}
			p.handleTTLInfoList(tt.args.contextID, tt.args.fqdn, tt.args.dnsttlinfolist, tt.args.updateOnly)
			wg.Wait()

			if tt.want.newEntry {
				for _, i := range tt.args.dnsttlinfolist {
					if _, err := p.IPToTTL.Get(i.ipaddress); err != nil {
						t.Errorf("no new entry for IP %q", i.ipaddress)
					}
				}
			}

			if tt.want.existingEntryIncreasedExpiry {
				for _, i := range tt.args.dnsttlinfolist {
					iptottlExisting, ok := tt.existing.ips[i.ipaddress]
					if !ok {
						t.Errorf("not in the existing map %q", i.ipaddress)
					}
					iptottlRaw, err := p.IPToTTL.Get(i.ipaddress)
					if err != nil {
						t.Errorf("no entry for IP %q", i.ipaddress)
					}
					iptottlUpdated := iptottlRaw.(iptottlinfo)

					if !iptottlUpdated.expiryTime.After(iptottlExisting.expiryTime) {
						t.Errorf("expiry time not updated")
					}
				}
			}
		})
	}
}

func TestProxy_Enforce(t *testing.T) {
	type args struct {
		contextID string
		puInfo    *policy.PUInfo
	}
	type existing struct {
		fqdns map[string]*dnsNamesToIP
		pus   map[string]*pucontext.PUContext
	}
	type want struct {
		fqdns map[string]*dnsNamesToIP
	}
	tests := []struct {
		name     string
		args     args
		existing existing
		want     want
		wantErr  bool
	}{
		{
			name: "if this is the first enforce call on a PU, simply initialize the data structures, with FQDNs from policy",
			args: args{
				contextID: contextID,
				puInfo: &policy.PUInfo{
					Runtime:   nil,
					ContextID: contextID,
					Policy: &policy.PUPolicy{
						DNSACLs: map[string][]policy.PortProtocolPolicy{
							fqdn: {
								{
									Ports:     []string{port80},
									Protocols: []string{constants.TCPProtoNum},
									Policy: &policy.FlowPolicy{
										ServiceID: serviceID,
									},
								},
							},
							fqdnTwo: {
								{
									Ports:     []string{port80},
									Protocols: []string{constants.TCPProtoNum},
									Policy: &policy.FlowPolicy{
										ServiceID: serviceID,
									},
								},
							},
						},
					},
				},
			},
			existing: existing{
				fqdns: map[string]*dnsNamesToIP{},
				pus:   map[string]*pucontext.PUContext{},
			},
			want: want{
				fqdns: map[string]*dnsNamesToIP{
					contextID: {
						nameToIP: map[string][]string{
							fqdn:    {},
							fqdnTwo: {},
						},
					},
				},
			},
		},
		{
			name: "new FQDNs from a policy simply register with the DNS proxy",
			args: args{
				contextID: contextID,
				puInfo: &policy.PUInfo{
					Runtime:   nil,
					ContextID: contextID,
					Policy: &policy.PUPolicy{
						DNSACLs: map[string][]policy.PortProtocolPolicy{
							fqdn: {
								{
									Ports:     []string{port80},
									Protocols: []string{constants.TCPProtoNum},
									Policy: &policy.FlowPolicy{
										ServiceID: serviceID,
									},
								},
							},
							fqdnTwo: {
								{
									Ports:     []string{port80},
									Protocols: []string{constants.TCPProtoNum},
									Policy: &policy.FlowPolicy{
										ServiceID: serviceID,
									},
								},
							},
						},
					},
				},
			},
			existing: existing{
				fqdns: map[string]*dnsNamesToIP{
					contextID: {
						nameToIP: map[string][]string{},
					},
				},
				pus: map[string]*pucontext.PUContext{},
			},
			want: want{
				fqdns: map[string]*dnsNamesToIP{
					contextID: {
						nameToIP: map[string][]string{
							fqdn:    {},
							fqdnTwo: {},
						},
					},
				},
			},
		},
		{
			name: "existing FQDNs update ipsets and ApplicationACLs",
			args: args{
				contextID: contextID,
				puInfo: &policy.PUInfo{
					Runtime:   nil,
					ContextID: contextID,
					Policy: &policy.PUPolicy{
						DNSACLs: map[string][]policy.PortProtocolPolicy{
							fqdn: {
								{
									Ports:     []string{port80},
									Protocols: []string{constants.TCPProtoNum},
									Policy: &policy.FlowPolicy{
										ServiceID: serviceID,
									},
								},
							},
							fqdnTwo: {
								{
									Ports:     []string{port80},
									Protocols: []string{constants.TCPProtoNum},
									Policy: &policy.FlowPolicy{
										ServiceID: serviceID,
									},
								},
							},
						},
					},
				},
			},
			existing: existing{
				fqdns: map[string]*dnsNamesToIP{
					contextID: {
						nameToIP: map[string][]string{
							fqdn:    {ip192_0_2_1},
							fqdnTwo: {ip192_0_2_2},
						},
					},
				},
				pus: map[string]*pucontext.PUContext{
					contextID: {
						RWMutex:         sync.RWMutex{},
						ApplicationACLs: acls.NewACLCache(),
						DNSACLs: map[string][]policy.PortProtocolPolicy{
							fqdn: {
								{
									Ports:     []string{port80},
									Protocols: []string{constants.TCPProtoNum},
									Policy: &policy.FlowPolicy{
										ServiceID: serviceID,
									},
								},
							},
						},
					},
				},
			},
			want: want{
				fqdns: map[string]*dnsNamesToIP{
					contextID: {
						nameToIP: map[string][]string{
							fqdn:    {ip192_0_2_1},
							fqdnTwo: {ip192_0_2_2},
						},
					},
				},
			},
		},
		{
			name: "existing FQDNs do not update ipsets and ApplicationACLs if PU context does not exist",
			args: args{
				contextID: contextID,
				puInfo: &policy.PUInfo{
					Runtime:   nil,
					ContextID: contextID,
					Policy: &policy.PUPolicy{
						DNSACLs: map[string][]policy.PortProtocolPolicy{
							fqdn: {
								{
									Ports:     []string{port80},
									Protocols: []string{constants.TCPProtoNum},
									Policy: &policy.FlowPolicy{
										ServiceID: serviceID,
									},
								},
							},
							fqdnTwo: {
								{
									Ports:     []string{port80},
									Protocols: []string{constants.TCPProtoNum},
									Policy: &policy.FlowPolicy{
										ServiceID: serviceID,
									},
								},
							},
						},
					},
				},
			},
			existing: existing{
				fqdns: map[string]*dnsNamesToIP{
					contextID: {
						nameToIP: map[string][]string{
							fqdn:    {ip192_0_2_1},
							fqdnTwo: {ip192_0_2_2},
						},
					},
				},
				pus: map[string]*pucontext.PUContext{},
			},
			want: want{
				fqdns: map[string]*dnsNamesToIP{
					contextID: {
						nameToIP: map[string][]string{
							fqdn:    {ip192_0_2_1},
							fqdnTwo: {ip192_0_2_2},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := &Proxy{
				puFromID:                 cache.NewCache("puFromContextID"),
				contextIDToServer:        map[string]*dns.Server{},
				contextIDToDNSNames:      cache.NewCache("contextIDtoDNSNames"),
				contextIDToDNSNamesLocks: newMutexMap(),
			}
			for k, v := range tt.existing.fqdns {
				p.contextIDToDNSNames.AddOrUpdate(k, v)
			}
			for k, v := range tt.existing.pus {
				p.puFromID.AddOrUpdate(k, v)
			}
			if err := p.Enforce(ctx, tt.args.contextID, tt.args.puInfo); (err != nil) != tt.wantErr {
				t.Errorf("Proxy.Enforce() error = %v, wantErr %v", err, tt.wantErr)
			}
			for contextID, wantFqdns := range tt.want.fqdns {
				existingFqdnsRaw, err := p.contextIDToDNSNames.Get(contextID)
				if err != nil {
					t.Errorf("no map for context %q in contextIDToDNSNames any longer", contextID)
				}
				existingFqdns := existingFqdnsRaw.(*dnsNamesToIP)
				if !reflect.DeepEqual(wantFqdns.nameToIP, existingFqdns.nameToIP) {
					t.Errorf("context %q: have fqdns %#v - want fqdns %#v", contextID, existingFqdns.nameToIP, wantFqdns.nameToIP)
				}
			}
		})
	}
}
