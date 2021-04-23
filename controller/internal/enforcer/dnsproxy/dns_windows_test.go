// +build windows

package dnsproxy

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/magiconair/properties/assert"
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/ipsetmanager"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cache"
)

func addDNSNamePolicy(context *pucontext.PUContext) {
	context.DNSACLs = policy.DNSRuleList{
		"google.com.": []policy.PortProtocolPolicy{
			{Ports: []string{"80"},
				Protocols: []string{"6"},
				Policy: &policy.FlowPolicy{
					Action:   policy.Accept,
					PolicyID: "2",
				}},
		},
	}
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

// CollectPacketEvent collects packet events from the datapath
func (d *DNSCollector) CollectPacketEvent(report *collector.PacketReport) {}

// CollectCounterEvent collect counters from the datapath
func (d *DNSCollector) CollectCounterEvent(report *collector.CounterReport) {}

// CollectPingEvent collects ping events from the datapath
func (d *DNSCollector) CollectPingEvent(report *collector.PingReport) {}

// CollectConnectionExceptionReport collects the connection exception report
func (d *DNSCollector) CollectConnectionExceptionReport(_ *collector.ConnectionExceptionReport) {}

var r collector.DNSRequestReport
var l sync.Mutex

// CollectDNSRequests collect counters from the datapath
func (d *DNSCollector) CollectDNSRequests(report *collector.DNSRequestReport) {
	l.Lock()
	r = *report
	l.Unlock()
}

const (
	dnsResponseHex1 = "45200048d22f00006a11ad8f08080808c0a8000e0035e7560034385a00088180000100010000000006676f6f676c6503636f6d0000010001c00c000100010000009d0004acd90d0e"
	dnsResponseHex2 = "45200054eb6700006a11944b08080808c0a8000e0035e7570040863400098180000100010000000006676f6f676c6503636f6d00001c0001c00c001c00010000012b00102607f8b040020c030000000000000066"
)

func TestDNS(t *testing.T) {
	puIDcache := cache.NewCache("puFromContextID")

	dnsResponsePacket1, _ := hex.DecodeString(dnsResponseHex1)
	dnsResponsePacket2, _ := hex.DecodeString(dnsResponseHex2)

	parsedPacket1, _ := packet.New(uint64(packet.PacketTypeNetwork), dnsResponsePacket1, "83", true)
	parsedPacket2, _ := packet.New(uint64(packet.PacketTypeNetwork), dnsResponsePacket2, "83", true)

	fp := &policy.PUInfo{
		Runtime: policy.NewPURuntimeWithDefaults(),
		Policy:  policy.NewPUPolicyWithDefaults(),
	}
	pu, _ := pucontext.NewPU("pu1", fp, nil, 24*time.Hour) // nolint

	findPU := func(id string) (*pucontext.PUContext, error) {
		if id == "pu1" {
			return pu, nil
		}
		return nil, errors.New("unknown PU")
	}

	addDNSNamePolicy(pu)

	puIDcache.AddOrUpdate("pu1", pu)
	collector := &DNSCollector{}

	ips := ipsetmanager.NewTestIpsetProvider()
	ipsetmanager.SetIpsetTestInstance(ips)
	proxy := New(context.Background(), puIDcache, nil, collector)

	err := proxy.StartDNSServer(context.Background(), "pu1", "53001")
	assert.Equal(t, err == nil, true, "start dns server")

	err = proxy.HandleDNSResponsePacket(parsedPacket1.GetUDPData(), parsedPacket1.SourceAddress(), parsedPacket1.SourcePort(), parsedPacket1.DestinationAddress(), parsedPacket1.DestPort(), findPU)
	assert.Equal(t, err == nil, true, "dns packet 1 failed")

	err = proxy.HandleDNSResponsePacket(parsedPacket2.GetUDPData(), parsedPacket2.SourceAddress(), parsedPacket2.SourcePort(), parsedPacket2.DestinationAddress(), parsedPacket2.DestPort(), findPU)
	assert.Equal(t, err == nil, true, "dns packet 2 failed")

	// wait a sec for report delivered via channel, and then expect one report since the next will be time-delayed
	time.Sleep(1 * time.Second)
	l.Lock()
	assert.Equal(t, r.NameLookup == "google.com.", true, "lookup should be google.com")
	assert.Equal(t, r.Count == 1, true, "count should be 1")
	l.Unlock()

	defaultFlowPolicy := &policy.FlowPolicy{Action: policy.Reject | policy.Log, PolicyID: "default", ServiceID: "default"}

	// test acls updated
	rpt, pkt, err := pu.ApplicationACLs.GetMatchingAction(net.ParseIP("172.217.13.14"), 80, packet.IPProtocolTCP, defaultFlowPolicy)
	assert.Equal(t, err == nil, true, "GetMatchingAction failed")
	assert.Equal(t, rpt.Action.Accepted(), true, "should be accepted (report)")
	assert.Equal(t, pkt.Action.Accepted(), true, "should be accepted (packet)")
	rpt, pkt, err = pu.ApplicationACLs.GetMatchingAction(net.ParseIP("2607:f8b0:4002:c03::66"), 80, packet.IPProtocolTCP, defaultFlowPolicy)
	assert.Equal(t, err == nil, true, "GetMatchingAction failed")
	assert.Equal(t, rpt.Action.Accepted(), true, "should be accepted (report)")
	assert.Equal(t, pkt.Action.Accepted(), true, "should be accepted (packet)")

	// test SyncWithPlatformCache
	clearWindowsDNSCacheFunc = func() error {
		return errors.New("error from unit test")
	}
	defer func() {
		clearWindowsDNSCacheFunc = clearWindowsDNSCache
	}()
	err = proxy.SyncWithPlatformCache(context.Background(), pu)
	assert.Equal(t, err != nil, true, "clearWindowsDNSCache not called with DNSACLs present")
	assert.Matches(t, err.Error(), "error from unit test")
	pu.DNSACLs = policy.DNSRuleList{}
	err = proxy.SyncWithPlatformCache(context.Background(), pu)
	assert.Equal(t, err == nil, true, "clearWindowsDNSCache called without DNSACLs present")

	proxy.ShutdownDNS("pu1")
}
