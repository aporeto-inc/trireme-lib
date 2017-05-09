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

	//AddExcludedIP adds exlcluded iplist
	AddExcludedIPsMock func(iplist []string) error

	// SetTargetNetworksMock  adds the SetTargetNetworks implementation
	SetTargetNetworksMock func(networks []string) error
}

// TestSupervisor is a test implementation for IptablesProvider
type TestSupervisor interface {
	Supervisor
	MockSupervise(t *testing.T, impl func(contextID string, puInfo *policy.PUInfo) error)
	MockUnsupervise(t *testing.T, impl func(contextID string) error)
	MockStart(t *testing.T, impl func() error)
	MockStop(t *testing.T, impl func() error)
	MockAddExcludedIPs(t *testing.T, impl func(ips []string) error)
	MockSetTargetNetworks(t *testing.T, impl func(networks []string) error)
}

// A TestSupervisorInst is an empty TransactionalManipulator that can be easily mocked.
type TestSupervisorInst struct {
	mocks       map[*testing.T]*mockedMethods
	lock        *sync.Mutex
	currentTest *testing.T
}

// NewTestSupervisor returns a new TestManipulator.
func NewTestSupervisor() *TestSupervisorInst {
	return &TestSupervisorInst{
		lock:  &sync.Mutex{},
		mocks: map[*testing.T]*mockedMethods{},
	}
}

// MockAddExcludedIPs mocks AddExcludedIPs
func (m *TestSupervisorInst) MockAddExcludedIPs(t *testing.T, impl func(ip []string) error) {
	m.currentMocks(t).AddExcludedIPsMock = impl
}

// MockSupervise mocks the Supervise method
func (m *TestSupervisorInst) MockSupervise(t *testing.T, impl func(contextID string, puInfo *policy.PUInfo) error) {

	m.currentMocks(t).superviseMock = impl
}

// MockUnsupervise mocks the unsupervise method
func (m *TestSupervisorInst) MockUnsupervise(t *testing.T, impl func(contextID string) error) {

	m.currentMocks(t).unsuperviseMock = impl
}

// MockStart mocks the Start method
func (m *TestSupervisorInst) MockStart(t *testing.T, impl func() error) {

	m.currentMocks(t).startMock = impl
}

// MockStop mocks the Stop method
func (m *TestSupervisorInst) MockStop(t *testing.T, impl func() error) {

	m.currentMocks(t).stopMock = impl
}

// MockSetTargetNetworks mocks the SetTargetNetworks method
func (m *TestSupervisorInst) MockSetTargetNetworks(t *testing.T, impl func(networks []string) error) {

	m.currentMocks(t).SetTargetNetworksMock = impl
}

// Supervise is a test implementation of the Supervise interface
func (m *TestSupervisorInst) Supervise(contextID string, puInfo *policy.PUInfo) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.superviseMock != nil {
		return mock.superviseMock(contextID, puInfo)
	}

	return nil
}

// Unsupervise is a test implementation of the Unsupervise interface
func (m *TestSupervisorInst) Unsupervise(contextID string) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.unsuperviseMock != nil {
		return mock.unsuperviseMock(contextID)
	}

	return nil
}

// AddExcludedIPs is a test implementation of the AddExcludedIPs interface
func (m *TestSupervisorInst) AddExcludedIPs(ips []string) error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.AddExcludedIPsMock != nil {
		return mock.AddExcludedIPsMock(ips)
	}
	return nil
}

// Start is a test implementation of the Start interface method
func (m *TestSupervisorInst) Start() error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.startMock != nil {
		return mock.startMock()
	}

	return nil
}

// Stop is a test implementation of the Stop interface method
func (m *TestSupervisorInst) Stop() error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.stopMock != nil {
		return mock.stopMock()
	}

	return nil
}

// SetTargetNetworks is a test implementation of the SetTargetNetworks interface method
func (m *TestSupervisorInst) SetTargetNetworks(networks []string) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.SetTargetNetworksMock != nil {
		return mock.SetTargetNetworksMock(networks)
	}

	return nil
}

func (m *TestSupervisorInst) currentMocks(t *testing.T) *mockedMethods {
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
