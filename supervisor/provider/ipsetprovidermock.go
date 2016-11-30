package provider

import (
	"sync"
	"testing"
)

type ipsetProviderMockedMethods struct {
	addMock       func(entry string, timeout int) error
	addOptionMock func(entry string, option string, timeout int) error
	delMock       func(entry string) error
	destroyMock   func() error
	flushMock     func() error
	testMock      func(entry string) (bool, error)
}

// TestIpsetProvider is a test implementation for IpsetProvider
type TestIpsetProvider interface {
	IpsetProvider
	MockAdd(t *testing.T, impl func(entry string, timeout int) error)
	MockAddOption(t *testing.T, impl func(entry string, option string, timeout int) error)
	MockDel(t *testing.T, impl func(entry string) error)
	MockDestroy(t *testing.T, impl func() error)
	MockFlush(t *testing.T, impl func() error)
	MockTest(t *testing.T, impl func(entry string) (bool, error))
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

func (m *testIpsetProvider) MockAdd(t *testing.T, impl func(entry string, timeout int) error) {

	m.currentMocks(t).addMock = impl
}

func (m *testIpsetProvider) MockAddOption(t *testing.T, impl func(entry string, option string, timeout int) error) {

	m.currentMocks(t).addOptionMock = impl
}

func (m *testIpsetProvider) MockDel(t *testing.T, impl func(entry string) error) {

	m.currentMocks(t).delMock = impl
}

func (m *testIpsetProvider) MockDestroy(t *testing.T, impl func() error) {

	m.currentMocks(t).destroyMock = impl
}

func (m *testIpsetProvider) MockFlush(t *testing.T, impl func() error) {

	m.currentMocks(t).flushMock = impl
}

func (m *testIpsetProvider) MockTest(t *testing.T, impl func(entry string) (bool, error)) {

	m.currentMocks(t).testMock = impl
}

func (m *testIpsetProvider) Add(entry string, timeout int) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.addMock != nil {
		return mock.addMock(entry, timeout)
	}

	return nil
}

func (m *testIpsetProvider) AddOption(entry string, option string, timeout int) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.addOptionMock != nil {
		return mock.addOptionMock(entry, option, timeout)
	}

	return nil
}

func (m *testIpsetProvider) Del(entry string) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.delMock != nil {
		return mock.delMock(entry)
	}

	return nil
}

func (m *testIpsetProvider) Destroy() error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.destroyMock != nil {
		return mock.destroyMock()
	}
	return nil

}

func (m *testIpsetProvider) Flush() error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.flushMock != nil {
		return mock.flushMock()
	}

	return nil
}

func (m *testIpsetProvider) Test(entry string) (bool, error) {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.testMock != nil {
		return mock.testMock(entry)
	}

	return false, nil
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
