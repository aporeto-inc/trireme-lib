package enforcer

import (
	"sync"
	"testing"

	"github.com/aporeto-inc/trireme/policy"
)

type mockedMethodsPolicyEnforcer struct {

	// Enforce starts enforcing policies for the given policy.PUInfo.
	enforceMock func(contextID string, puInfo *policy.PUInfo) error

	// Unenforce stops enforcing policy for the given IP.
	unenforceMock func(ip string) error

	// UpdatePU will be deprecated soon.
	updatePUMock func(ip string, puInfo *policy.PUInfo) error

	// GetFilterQueue returns the current FilterQueueConfig.
	getFilterQueueMock func() *FilterQueue

	// Start starts the Supervisor.
	startMock func() error

	// Stop stops the Supervisor.
	stopMock func() error
}

// TestPolicyEnforcer vxcv
type TestPolicyEnforcer interface {
	PolicyEnforcer
	MockEnforce(t *testing.T, impl func(contextID string, puInfo *policy.PUInfo) error)
	MockUnenforce(t *testing.T, impl func(ip string) error)
	MockUpdatePU(t *testing.T, impl func(ip string, puInfo *policy.PUInfo) error)
	MockGetFilterQueue(t *testing.T, impl func() *FilterQueue)
	MockStart(t *testing.T, impl func() error)
	MockStop(t *testing.T, impl func() error)
}

// A testSupervisor is an empty TransactionalManipulator that can be easily mocked.
type testPolicyEnforcer struct {
	mocks       map[*testing.T]*mockedMethodsPolicyEnforcer
	lock        *sync.Mutex
	currentTest *testing.T
}

// NewTestPolicyEnforcer returns a new TestManipulator.
func NewTestPolicyEnforcer() TestPolicyEnforcer {
	return &testPolicyEnforcer{
		lock:  &sync.Mutex{},
		mocks: map[*testing.T]*mockedMethodsPolicyEnforcer{},
	}
}

func (m *testPolicyEnforcer) MockEnforce(t *testing.T, impl func(contextID string, puInfo *policy.PUInfo) error) {

	m.currentMocks(t).enforceMock = impl
}

func (m *testPolicyEnforcer) MockUnenforce(t *testing.T, impl func(ip string) error) {

	m.currentMocks(t).unenforceMock = impl
}

func (m *testPolicyEnforcer) MockUpdatePU(t *testing.T, impl func(ip string, puInfo *policy.PUInfo) error) {

	m.currentMocks(t).updatePUMock = impl
}

func (m *testPolicyEnforcer) MockGetFilterQueue(t *testing.T, impl func() *FilterQueue) {

	m.currentMocks(t).getFilterQueueMock = impl
}

func (m *testPolicyEnforcer) MockStart(t *testing.T, impl func() error) {

	m.currentMocks(t).startMock = impl
}

func (m *testPolicyEnforcer) MockStop(t *testing.T, impl func() error) {

	m.currentMocks(t).stopMock = impl
}

func (m *testPolicyEnforcer) Enforce(contextID string, puInfo *policy.PUInfo) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.enforceMock != nil {
		return mock.enforceMock(contextID, puInfo)
	}

	return nil
}

func (m *testPolicyEnforcer) Unenforce(ip string) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.unenforceMock != nil {
		return mock.unenforceMock(ip)
	}

	return nil
}

func (m *testPolicyEnforcer) UpdatePU(ip string, puInfo *policy.PUInfo) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.updatePUMock != nil {
		return mock.updatePUMock(ip, puInfo)
	}

	return nil
}

func (m *testPolicyEnforcer) GetFilterQueue() *FilterQueue {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.getFilterQueueMock != nil {
		return mock.getFilterQueueMock()
	}

	return nil
}

func (m *testPolicyEnforcer) Start() error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.startMock != nil {
		return mock.startMock()
	}

	return nil
}

func (m *testPolicyEnforcer) Stop() error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.stopMock != nil {
		return mock.stopMock()
	}

	return nil
}

func (m *testPolicyEnforcer) currentMocks(t *testing.T) *mockedMethodsPolicyEnforcer {
	m.lock.Lock()
	defer m.lock.Unlock()

	mocks := m.mocks[t]

	if mocks == nil {
		mocks = &mockedMethodsPolicyEnforcer{}
		m.mocks[t] = mocks
	}

	m.currentTest = t
	return mocks
}
