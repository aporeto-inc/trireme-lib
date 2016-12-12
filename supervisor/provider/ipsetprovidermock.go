package provider

import (
	"sync"
	"testing"

	"github.com/bvandewalle/go-ipset/ipset"
)

type ipsetProviderMockedMethods struct {
	newMockIPset   func(name string, hasht string, p *ipset.Params) (Ipset, error)
	destroyAllMock func() error
}

// TestIpsetProvider is a test implementation for IpsetProvider
type TestIpsetProvider interface {
	IpsetProvider
	MockNewIpset(t *testing.T, impl func(name string, hasht string, p *ipset.Params) (Ipset, error))
	MockDestroyAll(t *testing.T, impl func() error)
}

type testIpsetProvider struct {
	mocks       map[*testing.T]*ipsetProviderMockedMethods
	lock        *sync.Mutex
	currentTest *testing.T
}

// NewTestIpsetProvider returns a new TestManipulator.
func NewTestIpsetProvider() TestIpsetProvider {
	return &testIpsetProvider{
		lock:  &sync.Mutex{},
		mocks: map[*testing.T]*ipsetProviderMockedMethods{},
	}
}

func (m *testIpsetProvider) MockNewIpset(t *testing.T, impl func(name string, hasht string, p *ipset.Params) (Ipset, error)) {

	m.currentMocks(t).newMockIPset = impl
}

func (m *testIpsetProvider) MockDestroyAll(t *testing.T, impl func() error) {

	m.currentMocks(t).destroyAllMock = impl
}

func (m *testIpsetProvider) NewIpset(name string, hasht string, p *ipset.Params) (Ipset, error) {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.newMockIPset != nil {
		return mock.newMockIPset(name, hasht, p)
	}

	return NewTestIpset(), nil
}

func (m *testIpsetProvider) DestroyAll() error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.destroyAllMock != nil {
		return mock.destroyAllMock()
	}

	return nil
}

func (m *testIpsetProvider) currentMocks(t *testing.T) *ipsetProviderMockedMethods {
	m.lock.Lock()
	defer m.lock.Unlock()

	mocks := m.mocks[t]

	if mocks == nil {
		mocks = &ipsetProviderMockedMethods{}
		m.mocks[t] = mocks
	}

	m.currentTest = t
	return mocks
}

type ipsetMockedMethods struct {
	addMock       func(entry string, timeout int) error
	addOptionMock func(entry string, option string, timeout int) error
	delMock       func(entry string) error
	destroyMock   func() error
	flushMock     func() error
	testMock      func(entry string) (bool, error)
}

// TestIpset is a test implementation for Ipset
type TestIpset interface {
	Ipset
	MockAdd(t *testing.T, impl func(entry string, timeout int) error)
	MockAddOption(t *testing.T, impl func(entry string, option string, timeout int) error)
	MockDel(t *testing.T, impl func(entry string) error)
	MockDestroy(t *testing.T, impl func() error)
	MockFlush(t *testing.T, impl func() error)
	MockTest(t *testing.T, impl func(entry string) (bool, error))
}

type testIpset struct {
	mocks       map[*testing.T]*ipsetMockedMethods
	lock        *sync.Mutex
	currentTest *testing.T
}

// NewTestIpset returns a new TestManipulator.
func NewTestIpset() TestIpset {
	return &testIpset{
		lock:  &sync.Mutex{},
		mocks: map[*testing.T]*ipsetMockedMethods{},
	}
}

func (m *testIpset) MockAdd(t *testing.T, impl func(entry string, timeout int) error) {

	m.currentMocks(t).addMock = impl
}

func (m *testIpset) MockAddOption(t *testing.T, impl func(entry string, option string, timeout int) error) {

	m.currentMocks(t).addOptionMock = impl
}

func (m *testIpset) MockDel(t *testing.T, impl func(entry string) error) {

	m.currentMocks(t).delMock = impl
}

func (m *testIpset) MockDestroy(t *testing.T, impl func() error) {

	m.currentMocks(t).destroyMock = impl
}

func (m *testIpset) MockFlush(t *testing.T, impl func() error) {

	m.currentMocks(t).flushMock = impl
}

func (m *testIpset) MockTest(t *testing.T, impl func(entry string) (bool, error)) {

	m.currentMocks(t).testMock = impl
}

func (m *testIpset) Add(entry string, timeout int) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.addMock != nil {
		return mock.addMock(entry, timeout)
	}

	return nil
}

func (m *testIpset) AddOption(entry string, option string, timeout int) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.addOptionMock != nil {
		return mock.addOptionMock(entry, option, timeout)
	}

	return nil
}

func (m *testIpset) Del(entry string) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.delMock != nil {
		return mock.delMock(entry)
	}

	return nil
}

func (m *testIpset) Destroy() error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.destroyMock != nil {
		return mock.destroyMock()
	}
	return nil

}

func (m *testIpset) Flush() error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.flushMock != nil {
		return mock.flushMock()
	}

	return nil
}

func (m *testIpset) Test(entry string) (bool, error) {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.testMock != nil {
		return mock.testMock(entry)
	}

	return false, nil
}

func (m *testIpset) currentMocks(t *testing.T) *ipsetMockedMethods {
	m.lock.Lock()
	defer m.lock.Unlock()

	mocks := m.mocks[t]

	if mocks == nil {
		mocks = &ipsetMockedMethods{}
		m.mocks[t] = mocks
	}

	m.currentTest = t
	return mocks
}
