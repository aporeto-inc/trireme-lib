package enforcerproxy

import (
	"sync"
	"testing"

	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/policy"
)

type mockedMethods struct {
	EnforceMock        func(contextID string, puInfo *policy.PUInfo) error
	UnenforceMock      func(contextID string) error
	GetFilterQueueMock func() *enforcer.FilterQueue
	StartMock          func() error
	StopMock           func() error
}

// TestEnforcerLauncher is a mock
type TestEnforcerLauncher interface {
	enforcer.PolicyEnforcer
	MockEnforce(t *testing.T, impl func(contextID string, puInfo *policy.PUInfo) error)
	MockUnenforce(t *testing.T, impl func(contextID string) error)
	MockGetFilterQueue(t *testing.T, impl func() *enforcer.FilterQueue)
	MockStart(t *testing.T, impl func() error)
	MockStop(t *testing.T, impl func() error)
}

type testEnforcerLauncher struct {
	mocks       map[*testing.T]*mockedMethods
	lock        *sync.Mutex
	currentTest *testing.T
}

// NewTestEnforcerLauncher mocks an enforcer
func NewTestEnforcerLauncher() enforcer.PolicyEnforcer {
	return &testEnforcerLauncher{
		lock:  &sync.Mutex{},
		mocks: map[*testing.T]*mockedMethods{},
	}
}

func (m *testEnforcerLauncher) currentMocks(t *testing.T) *mockedMethods {
	m.lock.Lock()
	defer m.lock.Unlock()

	mocks := m.mocks[t]

	if mocks == nil {
		mocks = &mockedMethods{}
		m.mocks[t] = mocks
	}

	m.currentTest = t
	return mocks
}

func (m *testEnforcerLauncher) MockEnforce(t *testing.T, impl func(contextID string, puInfo *policy.PUInfo) error) {
	m.currentMocks(t).EnforceMock = impl
}
func (m *testEnforcerLauncher) MockUnenforce(t *testing.T, impl func(contextID string) error) {
	m.currentMocks(t).UnenforceMock = impl
}
func (m *testEnforcerLauncher) MockGetFilterQueue(t *testing.T, impl func() *enforcer.FilterQueue) {
	m.currentMocks(t).GetFilterQueueMock = impl
}
func (m *testEnforcerLauncher) MockStart(t *testing.T, impl func() error) {
	m.currentMocks(t).StartMock = impl
}
func (m *testEnforcerLauncher) MockStop(t *testing.T, impl func() error) {
	m.currentMocks(t).StartMock = impl
}

func (m *testEnforcerLauncher) Enforce(contextID string, puInfo *policy.PUInfo) error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.EnforceMock != nil {
		return mock.EnforceMock(contextID, puInfo)

	}
	return nil
}
func (m *testEnforcerLauncher) Unenforce(contextID string) error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.UnenforceMock != nil {
		return mock.UnenforceMock(contextID)

	}
	return nil
}
func (m *testEnforcerLauncher) GetFilterQueue() *enforcer.FilterQueue {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.GetFilterQueueMock != nil {
		return mock.GetFilterQueueMock()

	}
	return nil
}
func (m *testEnforcerLauncher) Start() error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.StartMock != nil {
		return mock.StartMock()

	}
	return nil
}
func (m *testEnforcerLauncher) Stop() error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.EnforceMock != nil {
		return mock.StartMock()

	}
	return nil
}
