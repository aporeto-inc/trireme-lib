// +build windows
// path of least resistance -- instead of wrapping multiple places from where we instantiate iptables provider we provide a dummy implementation
// We can use the same functions to implement our own api later
package provider

type winiptables struct{}

// NewGoIPTablesProvider returns an IptablesProvider interface based on the go-iptables
// external package.
func NewGoIPTablesProvider() (IptablesProvider, error) {
	return &winiptables{}, nil
}

// Append apends a rule to chain of table
func (w *winiptables) Append(table, chain string, rulespec ...string) error {
	return nil
}

// Insert inserts a rule to a chain of table at the required pos
func (w *winiptables) Insert(table, chain string, pos int, rulespec ...string) error {
	return nil
}

// Delete deletes a rule of a chain in the given table
func (w *winiptables) Delete(table, chain string, rulespec ...string) error {
	return nil
}

// ListChains lists all the chains associated with a table
func (w *winiptables) ListChains(table string) ([]string, error) {
	return []string{}, nil
}

// ClearChain clears a chain in a table
func (w *winiptables) ClearChain(table, chain string) error {
	return nil
}

// DeleteChain deletes a chain in the table. There should be no references to this chain
func (w *winiptables) DeleteChain(table, chain string) error {
	return nil
}

// NewChain creates a new chain
func (w *winiptables) NewChain(table, chain string) error {
	return nil
}
