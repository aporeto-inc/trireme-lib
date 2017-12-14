package provider

import "github.com/coreos/go-iptables/iptables"

// IptablesProvider is an abstraction of all the methods an implementation of userspace
// iptables need to provide.
type IptablesProvider interface {
	Append(table, chain string, rulespec ...string) error
	Insert(table, chain string, pos int, rulespec ...string) error
	Delete(table, chain string, rulespec ...string) error
	ListChains(table string) ([]string, error)
	ClearChain(table, chain string) error
	DeleteChain(table, chain string) error
	NewChain(table, chain string) error
}

// NewGoIPTablesProvider returns an IptablesProvider interface based on the go-iptables
// external package.
func NewGoIPTablesProvider() (IptablesProvider, error) {
	return iptables.New()
}
