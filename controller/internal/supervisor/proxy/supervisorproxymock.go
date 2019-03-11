package supervisorproxy

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.aporeto.io/trireme-lib/controller/internal/supervisor"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
)

type mockedMethods struct {
	SuperviseMock                   func(string, *policy.PUInfo) error
	UnsuperviseMock                 func(string) error
	RunMock                         func(ctx context.Context) error
	SetTargetNetworksMock           func(cfg *runtime.Configuration) error
	CleanUpMock                     func() error
	EnableIPTablesPacketTracingMock func(ctx context.Context, contextID string, interval time.Duration) error
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

func (m *testSupervisorLauncher) MockEnableIPTablesPacketTracing(t *testing.T, impl func(context.Context, string, time.Duration) error) {
	m.currentMocks(t).EnableIPTablesPacketTracingMock = impl
}

func (m *testSupervisorLauncher) MockUnsupervise(t *testing.T, impl func(string) error) {
	m.currentMocks(t).UnsuperviseMock = impl
}

func (m *testSupervisorLauncher) MockRun(t *testing.T, impl func(ctx context.Context) error) {
	m.currentMocks(t).RunMock = impl
}

func (m *testSupervisorLauncher) MockSetTargetNetworks(t *testing.T, impl func(*runtime.Configuration) error) {
	m.currentMocks(t).SetTargetNetworksMock = impl
}

func (m *testSupervisorLauncher) MockCleanUp(t *testing.T, impl func() error) {
	m.currentMocks(t).CleanUpMock = impl
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

func (m *testSupervisorLauncher) SetTargetNetworks(cfg *runtime.Configuration) error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.SetTargetNetworksMock != nil {
		return mock.SetTargetNetworksMock(cfg)
	}
	return nil
}

func (m *testSupervisorLauncher) CleanUp() error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.CleanUpMock != nil {
		return mock.CleanUpMock()
	}
	return nil
}

func (m *testSupervisorLauncher) EnableIPTablesPacketTracing(ctx context.Context, contextID string, interval time.Duration) error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.EnableIPTablesPacketTracingMock != nil {
		return mock.EnableIPTablesPacketTracingMock(ctx, contextID, interval)
	}

	return nil
}
