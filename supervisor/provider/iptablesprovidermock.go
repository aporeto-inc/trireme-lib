package provider

import (
	"sync"
	"testing"
)

type iptablesProviderMockedMethods struct {
	appendMock      func(table, chain string, rulespec ...string) error
	insertMock      func(table, chain string, pos int, rulespec ...string) error
	deleteMock      func(table, chain string, rulespec ...string) error
	listChainsMock  func(table string) ([]string, error)
	clearChainMock  func(table, chain string) error
	deleteChainMock func(table, chain string) error
	newChainMock    func(table, chain string) error
}

// TestIptablesProvider is a test implementation for IptablesProvider
type TestIptablesProvider interface {
	IptablesProvider
	MockAppend(t *testing.T, impl func(table, chain string, rulespec ...string) error)
	MockInsert(t *testing.T, impl func(table, chain string, pos int, rulespec ...string) error)
	MockDelete(t *testing.T, impl func(table, chain string, rulespec ...string) error)
	MockListChains(t *testing.T, impl func(table string) ([]string, error))
	MockClearChain(t *testing.T, impl func(table, chain string) error)
	MockDeleteChain(t *testing.T, impl func(table, chain string) error)
	MockNewChain(t *testing.T, impl func(table, chain string) error)
}

// A testIptablesProvider is an empty TransactionalManipulator that can be easily mocked.
type testIptablesProvider struct {
	mocks       map[*testing.T]*iptablesProviderMockedMethods
	lock        *sync.Mutex
	currentTest *testing.T
}

// NewTestIptablesProvider returns a new TestManipulator.
func NewTestIptablesProvider() TestIptablesProvider {
	return &testIptablesProvider{
		lock:  &sync.Mutex{},
		mocks: map[*testing.T]*iptablesProviderMockedMethods{},
	}
}

func (m *testIptablesProvider) MockAppend(t *testing.T, impl func(table, chain string, rulespec ...string) error) {

	m.currentMocks(t).appendMock = impl
}

func (m *testIptablesProvider) MockInsert(t *testing.T, impl func(table, chain string, pos int, rulespec ...string) error) {

	m.currentMocks(t).insertMock = impl
}

func (m *testIptablesProvider) MockDelete(t *testing.T, impl func(table, chain string, rulespec ...string) error) {

