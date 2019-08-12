package nfqdatapath

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/magiconair/properties/assert"
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/policy"
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

	secret, _ := secrets.NewCompactPKI([]byte(secrets.PrivateKeyPEM), []byte(secrets.PublicPEM), []byte(secrets.CAPEM), secrets.CreateTxtToken(), claimsheader.CompressionTypeNone) //nolint
	collector := &collector.DefaultCollector{}

	// mock the call
	prevRawSocket := GetUDPRawSocket
	defer func() {
		GetUDPRawSocket = prevRawSocket
	}()
	GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
		return nil, nil
	}

	enforcer := NewWithDefaults(testServerID, collector, nil, secret, constants.RemoteContainer, "/proc", []string{"0.0.0.0/0"})
	enforcer.packetLogs = true

	puInfo := policy.NewPUInfo("SomePU", "/ns", common.ContainerPU)
	pucontext, _ := pucontext.NewPU("SomePU", puInfo, 10*time.Second) //nolint

	addDNSNamePolicy(pucontext)

	enforcer.puFromMark.AddOrUpdate("100", pucontext)
	enforcer.mode = constants.LocalServer

	enforcer.conntrack = &flowClientDummy{}
	server := enforcer.startDNSServer("53001")
	assert.Equal(t, server != nil, true, "We should be able to create a dns server")

	resolver := createCustomResolver()
	ctx := context.Background()
	resolver.LookupIPAddr(ctx, "www.google.com") //nolint
	err = server.Shutdown()
	assert.Equal(t, err == nil, true, "err should be nil")
}
