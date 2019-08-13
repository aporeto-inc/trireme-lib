package dnsproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/magiconair/properties/assert"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
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

func (c *flowClientDummy) GetOriginalDest(ipSrc, ipDst net.IP, srcport, dstport uint16, protonum uint8) (net.IP, uint16, uint32, error) {
	return net.ParseIP("8.8.8.8"), 53, 100, nil
}

func addDNSNamePolicy(context *pucontext.PUContext) {
	context.DNSACLs = policy.DNSRuleList{
		"www.google.com": []policy.PortProtocolPolicy{
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

func TestDNS(t *testing.T) {
	puIDcache := cache.NewCache("puFromContextID")

	fp := &policy.PUInfo{
		Runtime: policy.NewPURuntimeWithDefaults(),
		Policy:  policy.NewPUPolicyWithDefaults(),
	}
	pu, _ := pucontext.NewPU("pu1", fp, 24*time.Hour) // nolint

	addDNSNamePolicy(pu)

	puIDcache.AddOrUpdate("pu1", pu)
	conntrack := &flowClientDummy{}

	proxy := New(puIDcache, conntrack)

	err := proxy.StartDNSServer("pu1", "53001")
	assert.Equal(t, err == nil, true, "start dns server")

	resolver := createCustomResolver()
	ctx := context.Background()
	resolver.LookupIPAddr(ctx, "www.google.com") //nolint

	assert.Equal(t, err == nil, true, "err should be nil")

	proxy.ShutdownDNS("pu1")
}
