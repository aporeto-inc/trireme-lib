// +build windows

package provider

import (
	"bytes"
	"sync"
)

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
	// Commit will commit changes if it is a batch provider.
	Commit() error
}

// BatchProvider uses iptables-restore to program ACLs
type BatchProvider struct {
	sync.Mutex
}

const (
	restoreCmd = "iptables-restore"
)

// NewGoIPTablesProvider returns an IptablesProvider interface based on the go-iptables
// external package.
func NewGoIPTablesProvider(batchTables []string) (*BatchProvider, error) {

	return &BatchProvider{}, nil
}

// Append will append the provided rule to the local cache or call
// directly the iptables command depending on the table.
func (b *BatchProvider) Append(table, chain string, rulespec ...string) error {

	return nil
}

// Insert will insert the rule in the corresponding position in the local
// cache or call the corresponding iptables command, depending on the table.
func (b *BatchProvider) Insert(table, chain string, pos int, rulespec ...string) error {

	return nil
}

// Delete will delete the rule from the local cache or the system.
func (b *BatchProvider) Delete(table, chain string, rulespec ...string) error {

	return nil
}

// ListChains will provide a list of the current chains.
func (b *BatchProvider) ListChains(table string) ([]string, error) {
	return []string{}, nil

}

// ClearChain will clear the chains.
func (b *BatchProvider) ClearChain(table, chain string) error {

	return nil
}

// DeleteChain will delete the chains.
func (b *BatchProvider) DeleteChain(table, chain string) error {

	return nil
}

// NewChain creates a new chain.
func (b *BatchProvider) NewChain(table, chain string) error {

	return nil
}

// Commit commits the rules to the system
func (b *BatchProvider) Commit() error {
	return nil
}

func (b *BatchProvider) createDataBuffer() (*bytes.Buffer, error) {

	buf := bytes.NewBuffer([]byte{})
	return buf, nil
}

// restore will save the current DB to iptables.
func (b *BatchProvider) restore() error {

	return nil
}

func restoreHasWait() bool {
	return false
}
