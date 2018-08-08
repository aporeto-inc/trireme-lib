// +build linux

package provider

import "github.com/coreos/go-iptables/iptables"

// NewGoIPTablesProvider returns an IptablesProvider interface based on the go-iptables
// external package.
func NewGoIPTablesProvider() (IptablesProvider, error) {
	return iptables.New()
}
