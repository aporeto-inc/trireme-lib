// +build windows

package provider

import (
	"bytes"
	"sync"

	"go.uber.org/zap"
)

// IptablesProvider is an abstraction of all the methods an implementation of userspace
// iptables need to provide.
type IptablesProvider interface {
	BaseIPTables
	// Commit will commit changes if it is a batch provider.
	Commit() error
	// RetrieveTable allows a caller to retrieve the final table.
	RetrieveTable() map[string]map[string][]string
}

// BaseIPTables is the base interface of iptables functions.
type BaseIPTables interface {
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

// BatchProvider uses iptables-restore to program ACLs
type BatchProvider struct {
	ipt BaseIPTables

	//        TABLE      CHAIN    RULES
	rules       map[string]map[string][]string
	batchTables map[string]bool

	// Allowing for custom commit functions for testing
	commitFunc func(buf *bytes.Buffer) error
	sync.Mutex
	restoreCmd string
}

const (
	restoreCmdV4 = "iptables-restore"
	restoreCmdV6 = "ip6tables-restore"
)

// NewGoIPTablesProviderV4 returns an IptablesProvider interface based on the go-iptables
// external package.
func NewGoIPTablesProviderV4(batchTables []string) (*BatchProvider, error) {
	return &BatchProvider{}, nil
}

// NewGoIPTablesProviderV6 returns an IptablesProvider interface based on the go-iptables
// external package.
func NewGoIPTablesProviderV6(batchTables []string) (*BatchProvider, error) {
	return &BatchProvider{}, nil
}

// NewCustomBatchProvider is a custom batch provider wher the downstream
// iptables utility is provided by the caller. Very useful for testing
// the ACL functions with a mock.
func NewCustomBatchProvider(ipt BaseIPTables, commit func(buf *bytes.Buffer) error, batchTables []string) *BatchProvider {
	return &BatchProvider{}
}

// Append will append the provided rule to the local cache or call
// directly the iptables command depending on the table.
func (b *BatchProvider) Append(table, chain string, rulespec ...string) error {
	zap.L().Error("Append",
		zap.String("Table", table),
		zap.String("Chain", chain),
		zap.Strings("Rules", rulespec))
	return nil
}

// Insert will insert the rule in the corresponding position in the local
// cache or call the corresponding iptables command, depending on the table.
func (b *BatchProvider) Insert(table, chain string, pos int, rulespec ...string) error {
	return nil
}

// Delete will delete the rule from the local cache or the system.
func (b *BatchProvider) Delete(table, chain string, rulespec ...string) error {
	zap.L().Error("Delete",
		zap.String("Table", table),
		zap.String("Chain", chain),
		zap.Strings("Rules", rulespec))

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
	zap.L().Error("NewCHain",
		zap.String("Table", table),
		zap.String("Chain", chain))
	return nil
}

// Commit commits the rules to the system
func (b *BatchProvider) Commit() error {
	return nil
}

// RetrieveTable allows a caller to retrieve the final table. Mostly
// needed for debuging and unit tests.
func (b *BatchProvider) RetrieveTable() map[string]map[string][]string {
	return map[string]map[string][]string{}
}
