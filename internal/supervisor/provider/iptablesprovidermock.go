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

	m.currentMocks(t).deleteMock = impl
}

func (m *testIptablesProvider) MockListChains(t *testing.T, impl func(table string) ([]string, error)) {

	m.currentMocks(t).listChainsMock = impl
}

func (m *testIptablesProvider) MockClearChain(t *testing.T, impl func(table, chain string) error) {

	m.currentMocks(t).clearChainMock = impl
}

func (m *testIptablesProvider) MockDeleteChain(t *testing.T, impl func(table, chain string) error) {

	m.currentMocks(t).deleteChainMock = impl
}

func (m *testIptablesProvider) MockNewChain(t *testing.T, impl func(table, chain string) error) {

	m.currentMocks(t).newChainMock = impl
}

func (m *testIptablesProvider) Append(table, chain string, rulespec ...string) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.appendMock != nil {
		return mock.appendMock(table, chain, rulespec...)
	}

	return nil
}

func (m *testIptablesProvider) Insert(table, chain string, pos int, rulespec ...string) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.insertMock != nil {
		return mock.insertMock(table, chain, pos, rulespec...)
	}

	return nil
}

func (m *testIptablesProvider) Delete(table, chain string, rulespec ...string) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.deleteMock != nil {
		return mock.deleteMock(table, chain, rulespec...)
	}

	return nil
}

func (m *testIptablesProvider) ListChains(table string) ([]string, error) {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.listChainsMock != nil {
		return mock.listChainsMock(table)
	}

	return nil, nil
}

func (m *testIptablesProvider) ClearChain(table, chain string) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.clearChainMock != nil {
		return mock.clearChainMock(table, chain)
	}

	return nil
}

func (m *testIptablesProvider) DeleteChain(table, chain string) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.deleteChainMock != nil {
		return mock.deleteChainMock(table, chain)
	}

	return nil
}

func (m *testIptablesProvider) NewChain(table, chain string) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.newChainMock != nil {
		return mock.newChainMock(table, chain)
	}

	return nil
}

func (m *testIptablesProvider) currentMocks(t *testing.T) *iptablesProviderMockedMethods {
	m.lock.Lock()
	defer m.lock.Unlock()

	mocks := m.mocks[t]

	if mocks == nil {
		mocks = &iptablesProviderMockedMethods{}
		m.mocks[t] = mocks
	}

	m.currentTest = t
	return mocks
}
