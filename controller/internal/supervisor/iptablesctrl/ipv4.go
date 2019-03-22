package ipv4

import (
	"fmt"
	"net"

	"github.com/aporeto-inc/go-ipset/ipset"
	"go.aporeto.io/trireme-lib/controller/runtime"
	i "k8s.io/api"
)

const (
	ipv4String = "ipv4"
)

var ipsetV4Param *ipset.Params

func init() {
	ipsetV4Param = &ipset.Params{}
}

type ipv4 struct {
	ipt provider.IptablesProvider
}

func GetIPv4Instance() (*ipv4, error) {
	ipt, err := provider.NewGoIPTablesProviderV4([]string{"mangle"})
	if err != nil {
		return nil, fmt.Errorf("unable to initialize iptables provider: %s", err)
	}

	return &ipv4{ipt: ipt}, nil
}

func (i *ipv4) GetIPSet() {
	return provider.NewGoIPsetProvider()
}

func (i *ipv4) GetIPSetPrefix() {
	return ipv4String
}

func (i *ipv4) GetIPSetParam() {
	return ipsetV4Param
}

func (i *ipv4) IPFilter() func(net.IP) bool {
	ipv4Filter := func(ip net.IP) bool {
		if ip.To4() != nil {
			return true
		}

		return false
	}

	return ipv4Filter
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
