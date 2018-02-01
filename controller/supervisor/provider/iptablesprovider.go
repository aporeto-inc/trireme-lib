package provider

import "github.com/coreos/go-iptables/iptables"

// IptablesProvider is an abstraction of all the methods an implementation of userspace
// iptables need to provide.
type IptablesProvider interface {
	// Append apends a rule to chain of table
	Append(table, chain string, rulespec ...string) error
	// Insert inserts a rule to a chain of table at the required pos
	Insert(table, chain string, pos int, rulespec ...string) error
	// Delete deletes a rule of a chain in the given table
	Delete(table, chain string, rulespec ...string) error
	// ListChains lists all the chains associated with a table
	ListChains(table string) ([]string, error)
	// ClearChain clears a chain in a table
	ClearChain(table, chain string) error
	// DeleteChain deletes a chain in the table. There should be no references to this chain
	DeleteChain(table, chain string) error
	// NewChain creates a new chain
	NewChain(table, chain string) error
}

// NewGoIPTablesProvider returns an IptablesProvider interface based on the go-iptables
// external package.
func NewGoIPTablesProvider() (IptablesProvider, error) {
	return iptables.New()
}
