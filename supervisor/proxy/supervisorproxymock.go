package supervisorproxy

import (
	"sync"
	"testing"

	"github.com/aporeto-inc/trireme/policy"
	"github.com/aporeto-inc/trireme/supervisor"
)

type mockedMethods struct {
	SuperviseMock         func(string, *policy.PUInfo) error
	UnsuperviseMock       func(string) error
	StartMock             func() error
	StopMock              func() error
	SetTargetNetworksMock func([]string) error
}

// TestSupervisorLauncher is a mock
type TestSupervisorLauncher interface {
	supervisor.Supervisor
}

type testSupervisorLauncher struct {
	mocks       map[*testing.T]*mockedMethods
	lock        *sync.Mutex
	currentTest *testing.T
}

// NewTestSupervisorLauncher creates a mock supervisor
func NewTestSupervisorLauncher() supervisor.Supervisor {
	return &testSupervisorLauncher{
		lock:  &sync.Mutex{},
		mocks: map[*testing.T]*mockedMethods{},
	}
}

func (m *testSupervisorLauncher) currentMocks(t *testing.T) *mockedMethods {
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

func (m *testSupervisorLauncher) MockSupervise(t *testing.T, impl func(string, *policy.PUInfo) error) {
	m.currentMocks(t).SuperviseMock = impl
}

func (m *testSupervisorLauncher) MockUnsupervise(t *testing.T, impl func(string) error) {
	m.currentMocks(t).UnsuperviseMock = impl
}

func (m *testSupervisorLauncher) MockStart(t *testing.T, impl func() error) {
	m.currentMocks(t).StartMock = impl
}

func (m *testSupervisorLauncher) MockSetTargetNetworks(t *testing.T, impl func([]string) error) {
	m.currentMocks(t).SetTargetNetworksMock = impl
}

func (m *testSupervisorLauncher) MockStop(t *testing.T, impl func() error) {
	m.currentMocks(t).StopMock = impl
}

func (m *testSupervisorLauncher) Supervise(contextID string, puInfo *policy.PUInfo) error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.SuperviseMock != nil {
		return mock.SuperviseMock(contextID, puInfo)

	}
	return nil
}

func (m *testSupervisorLauncher) Unsupervise(contextID string) error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.UnsuperviseMock != nil {
		return mock.UnsuperviseMock(contextID)

	}
	return nil
}

func (m *testSupervisorLauncher) Start() error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.StartMock != nil {
		return mock.StartMock()

	}
	return nil
}

func (m *testSupervisorLauncher) SetTargetNetworks(networls []string) error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.StartMock != nil {
		return mock.StartMock()

	}
	return nil
}

func (m *testSupervisorLauncher) Stop() error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.StopMock != nil {
		return mock.StopMock()

	}
	return nil
}
