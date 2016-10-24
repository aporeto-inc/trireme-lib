package supervisor

import (
	"sync"
	"testing"

	"github.com/aporeto-inc/trireme/policy"
)

type mockedMethods struct {

	// Supervise adds a new supervised processing unit.
	superviseMock func(contextID string, puInfo *policy.PUInfo) error

	// Unsupervise unsupervises the given PU
	unsuperviseMock func(contextID string) error

	// Start starts the Supervisor.
	startMock func() error

	// Stop stops the Supervisor.
	stopMock func() error
}

// TestSupervisor us
type TestSupervisor interface {
	Supervisor
	MockSupervise(t *testing.T, impl func(contextID string, puInfo *policy.PUInfo) error)
	MockUnsupervise(t *testing.T, impl func(contextID string) error)
	MockStart(t *testing.T, impl func() error)
	MockStop(t *testing.T, impl func() error)
}

// A testSupervisor is an empty TransactionalManipulator that can be easily mocked.
type testSupervisor struct {
	mocks       map[*testing.T]*mockedMethods
	lock        *sync.Mutex
	currentTest *testing.T
}

// NewTestSupervisor returns a new TestManipulator.
func NewTestSupervisor() TestSupervisor {
	return &testSupervisor{
		lock:  &sync.Mutex{},
		mocks: map[*testing.T]*mockedMethods{},
	}
}

func (m *testSupervisor) MockSupervise(t *testing.T, impl func(contextID string, puInfo *policy.PUInfo) error) {

	m.currentMocks(t).superviseMock = impl
}

func (m *testSupervisor) MockUnsupervise(t *testing.T, impl func(contextID string) error) {

	m.currentMocks(t).unsuperviseMock = impl
}

func (m *testSupervisor) MockStart(t *testing.T, impl func() error) {

	m.currentMocks(t).startMock = impl
}

func (m *testSupervisor) MockStop(t *testing.T, impl func() error) {

	m.currentMocks(t).stopMock = impl
}

func (m *testSupervisor) Supervise(contextID string, puInfo *policy.PUInfo) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.superviseMock != nil {
		return mock.superviseMock(contextID, puInfo)
	}

	return nil
}

func (m *testSupervisor) Unsupervise(contextID string) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.unsuperviseMock != nil {
		return mock.unsuperviseMock(contextID)
	}

	return nil
}

func (m *testSupervisor) Start() error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.startMock != nil {
		return mock.startMock()
	}

	return nil
}

func (m *testSupervisor) Stop() error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.stopMock != nil {
		return mock.stopMock()
	}

	return nil
}

func (m *testSupervisor) currentMocks(t *testing.T) *mockedMethods {
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
