package nfqdatapath

import (
	"context"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

type serveDNS struct {
	*Datapath
}

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
		Timeout: 500 * time.Millisecond,
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
	lAddr := w.LocalAddr().(*net.UDPAddr)
	rAddr := w.RemoteAddr().(*net.UDPAddr)

	origIP, origPort, mark, err := s.conntrack.GetOriginalDest(net.ParseIP("127.0.0.1"), rAddr.IP, uint16(lAddr.Port), uint16(rAddr.Port), 17)
	if err != nil {
		zap.L().Error("Failed to find flow for the redirected dns traffic", zap.Error(err))
		return
	}

	puCtx, err := s.contextFromIP(true, strconv.Itoa(int(mark)), 0, packet.IPProtocolUDP)
	if err != nil {
		zap.L().Error("context not found for the PU with mark", zap.Int("mark", int(mark)), zap.Error(err))
		return
	}

	dnsReply, ips, err := forwardDNSReq(r, origIP, origPort)
	if err != nil {
		zap.L().Debug("Forwarded dns request returned error", zap.Error(err))
		return
	}

	ps, err := puCtx.GetPolicyFromFQDN(r.Question[0].Name)
	if err == nil {
		for _, p := range ps {
			if err := puCtx.UpdateApplicationACLs(policy.IPRuleList{{Addresses: ips,
				Ports:     p.Ports,
				Protocols: p.Protocols,
				Policy:    p.Policy,
			}}); err != nil {
				zap.L().Error("Adding IP rule returned error", zap.Error(err))
			}
		}
	}

	if err := w.WriteMsg(dnsReply); err != nil {
		zap.L().Error("Writing dns response back to the client returned error", zap.Error(err))
	}
}

func (d *Datapath) startDNSServer(port string) *dns.Server {

	netPacketConn, err := listenUDP("udp", "127.0.0.1:"+port)
	if err != nil {
		zap.L().Error("Error starting dns server", zap.Error(err))
		return nil
	}

	server := &dns.Server{PacketConn: netPacketConn, Handler: &serveDNS{d}}
	go func() {
		if err := server.ActivateAndServe(); err != nil {
			zap.L().Error("Could not start DNS proxy server", zap.Error(err))
		}
	}()

	return server
}
