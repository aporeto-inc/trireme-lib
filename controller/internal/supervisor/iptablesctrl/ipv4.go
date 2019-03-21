package ipv4

import (
	"net"

	"github.com/aporeto-inc/go-ipset/ipset"
	"go.aporeto.io/trireme-lib/controller/runtime"
	i "k8s.io/api"
)

const (
	ipv4 = "ipv4"
)

var ipsetV4Param *ipset.Params

func init() {
	ipsetV4Param = &ipset.Params{}
}

func Setup(cfg) {

}

func () ipsetParms() {
	return ipsetV4Param
}

func filterIPv4(c *runtime.Configuration) *runtime.Configuration {
	filter := func(ips []string) {
		var filteredIPs []string

		for _, ip := range ips {
			netIP, _, _ := net.ParseCIDR(ip)
			if netIP.To4() != nil {
				filteredIPs = append(filteredIPs, ip)
			}
		}

		return filteredIPs
	}

	return &runtime.Configuration{
		TCPTargetNetworks: filter(c.TCPTargetNetworks),
		UDPTargetNetworks: filter(c.UDPTargetNetworks),
		ExcludedNetworks:  filter(c.ExcludedNetworks),
	}
}

// SetTargetNetworks updates ths target networks. There are three different
// types of target networks:
//   - TCPTargetNetworks for TCP traffic (by default 0.0.0.0/0)
//   - UDPTargetNetworks for UDP traffic (by default empty)
//   - ExcludedNetworks that are always ignored (by default empty)

func (ipt *ipt) SetTargetNetworks(c *runtime.Configuration) error {

	if c == nil {
		return nil
	}

	cfg := filterIPv4(cfg)

	var oldConfig *runtime.Configuration
	if i.iptInstance.cfg == nil {
		oldConfig = &runtime.Configuration{}
	} else {
		oldConfig = i.iptInstance.cfg.DeepCopy()
	}

	// If there are no target networks, capture all traffic
	if len(cfg.TCPTargetNetworks) == 0 {
		cfg.TCPTargetNetworks = []string{"0.0.0.0/1", "128.0.0.0/1"}
	}

	if err := i.updateAllTargetNetworks(cfg, oldConfig); err != nil {
		return err
	}

	ipt.cfg = cfg

	return nil
}
