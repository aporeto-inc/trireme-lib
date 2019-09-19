package iptablesctrl

import (
	"fmt"
	"net"
	"strings"

	"github.com/aporeto-inc/go-ipset/ipset"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
)

const (
	ipv4String = "v4-"
	// IPv4DefaultIP is the default ip address of ipv4 subnets
	IPv4DefaultIP = "0.0.0.0/0"
)

var ipsetV4Param *ipset.Params

type ipv4 struct {
	ipt provider.IptablesProvider
}

func init() {
	ipsetV4Param = &ipset.Params{}
}

// GetIPv4Impl creates the instance of ipv4 struct which implements the interface
// ipImpl
func GetIPv4Impl() (IPImpl, error) {
	ipt, err := provider.NewGoIPTablesProviderV4([]string{"mangle"})
	if err != nil {
		return nil, fmt.Errorf("unable to initialize iptables provider: %s", err)
	}

	return &ipv4{ipt: ipt}, nil
}

func (i *ipv4) GetIPSetPrefix() string {
	return chainPrefix + ipv4String
}

func (i *ipv4) GetIPSetParam() *ipset.Params {
	return ipsetV4Param
}

func (i *ipv4) IPFilter() func(net.IP) bool {
	ipv4Filter := func(ip net.IP) bool {
		return (ip.To4() != nil)
	}

	return ipv4Filter
}

func (i *ipv4) GetDefaultIP() string {
	return IPv4DefaultIP
}

func (i *ipv4) NeedICMP() bool {
	return false
}

func (i *ipv4) ProtocolAllowed(proto string) bool {

	return !(strings.ToLower(proto) == "icmpv6")
}

func (i *ipv4) Append(table, chain string, rulespec ...string) error {
	return i.ipt.Append(table, chain, rulespec...)
}

func (i *ipv4) Insert(table, chain string, pos int, rulespec ...string) error {
	return i.ipt.Insert(table, chain, pos, rulespec...)
}

func (i *ipv4) ListChains(table string) ([]string, error) {
	return i.ipt.ListChains(table)
}

func (i *ipv4) ClearChain(table, chain string) error {
	return i.ipt.ClearChain(table, chain)
}

func (i *ipv4) DeleteChain(table, chain string) error {
	return i.ipt.DeleteChain(table, chain)
}

func (i *ipv4) NewChain(table, chain string) error {
	return i.ipt.NewChain(table, chain)
}

func (i *ipv4) Commit() error {
	return i.ipt.Commit()
}

func (i *ipv4) Delete(table, chain string, rulespec ...string) error {
	return i.ipt.Delete(table, chain, rulespec...)
}

func (i *ipv4) RetrieveTable() map[string]map[string][]string {
	return i.ipt.RetrieveTable()
}
