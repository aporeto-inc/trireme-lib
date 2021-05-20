// +build !windows

package iptablesctrl

import (
	provider "go.aporeto.io/enforcerd/trireme-lib/controller/pkg/aclprovider"
)

// GetIPv6Impl creates the instance of ipv6 struct which implements
// the interface ipImpl
func GetIPv6Impl(ipv6Enabled bool) (IPImpl, error) {
	ipt, err := provider.NewGoIPTablesProviderV6([]string{"mangle"}, CustomQOSChain)
	if err == nil {
		// test if the system supports ip6tables
		if _, err = ipt.ListChains("mangle"); err == nil {
			return &ipv6{ipt: ipt, ipv6Enabled: ipv6Enabled}, nil
		}
	}

	return &ipv6{ipt: nil, ipv6Enabled: false}, nil
}
