package supervisorproxy

import (
	"context"
	"sync"
	"testing"

	"github.com/aporeto-inc/trireme-lib/controller/supervisor"
	"github.com/aporeto-inc/trireme-lib/policy"
)

type mockedMethods struct {
	SuperviseMock         func(string, *policy.PUInfo) error
	UnsuperviseMock       func(string) error
	RunMock               func(ctx context.Context) error
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

func (m *testSupervisorLauncher) MockRun(t *testing.T, impl func(ctx context.Context) error) {
	m.currentMocks(t).RunMock = impl
}

func (m *testSupervisorLauncher) MockSetTargetNetworks(t *testing.T, impl func([]string) error) {
	m.currentMocks(t).SetTargetNetworksMock = impl
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

func (m *testSupervisorLauncher) Run(ctx context.Context) error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.RunMock != nil {
		return mock.RunMock(ctx)

	}
	return nil
}

func (m *testSupervisorLauncher) SetTargetNetworks(networks []string) error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.SetTargetNetworksMock != nil {
		return mock.SetTargetNetworksMock(networks)

	}
	return nil
}
