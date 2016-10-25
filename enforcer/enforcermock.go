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

	// GetFilterQueue returns the current FilterQueueConfig.
	getFilterQueueMock func() *FilterQueue

	// Start starts the Supervisor.
	startMock func() error

	// Stop stops the Supervisor.
	stopMock func() error
}

type mockedMethodsPublicKeyAdder struct {
	// PublicKeyAdd adds the given cert for the given host.
	publicKeyAddMock func(host string, cert []byte) error
}

// TestPolicyEnforcer vxcv
type TestPolicyEnforcer interface {
	PolicyEnforcer
	MockEnforce(t *testing.T, impl func(contextID string, puInfo *policy.PUInfo) error)
	MockUnenforce(t *testing.T, impl func(ip string) error)
	MockGetFilterQueue(t *testing.T, impl func() *FilterQueue)
	MockStart(t *testing.T, impl func() error)
	MockStop(t *testing.T, impl func() error)
}

// TestPublicKeyAdder vxcv
type TestPublicKeyAdder interface {
	PublicKeyAdder
	MockPublicKeyAdd(t *testing.T, impl func(host string, cert []byte) error)
}

// A testPolicyEnforcer is an empty TransactionalManipulator that can be easily mocked.
type testPolicyEnforcer struct {
	mocks       map[*testing.T]*mockedMethodsPolicyEnforcer
	lock        *sync.Mutex
	currentTest *testing.T
}

// A testPublicKeyAdder is an empty TransactionalManipulator that can be easily mocked.
type testPublicKeyAdder struct {
	mocks       map[*testing.T]*mockedMethodsPublicKeyAdder
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

// NewTestPublicKeyAdder returns a new TestManipulator.
func NewTestPublicKeyAdder() TestPublicKeyAdder {
	return &testPublicKeyAdder{
		lock:  &sync.Mutex{},
		mocks: map[*testing.T]*mockedMethodsPublicKeyAdder{},
	}
}

func (m *testPolicyEnforcer) MockEnforce(t *testing.T, impl func(contextID string, puInfo *policy.PUInfo) error) {

	m.currentMocksPolicyEnforcer(t).enforceMock = impl
}

func (m *testPolicyEnforcer) MockUnenforce(t *testing.T, impl func(ip string) error) {

	m.currentMocksPolicyEnforcer(t).unenforceMock = impl
}

func (m *testPolicyEnforcer) MockGetFilterQueue(t *testing.T, impl func() *FilterQueue) {

	m.currentMocksPolicyEnforcer(t).getFilterQueueMock = impl
}

func (m *testPolicyEnforcer) MockStart(t *testing.T, impl func() error) {

	m.currentMocksPolicyEnforcer(t).startMock = impl
}

func (m *testPolicyEnforcer) MockStop(t *testing.T, impl func() error) {

	m.currentMocksPolicyEnforcer(t).stopMock = impl
}

func (m *testPolicyEnforcer) Enforce(contextID string, puInfo *policy.PUInfo) error {

	if mock := m.currentMocksPolicyEnforcer(m.currentTest); mock != nil && mock.enforceMock != nil {
		return mock.enforceMock(contextID, puInfo)
	}

	return nil
}

func (m *testPolicyEnforcer) Unenforce(ip string) error {

	if mock := m.currentMocksPolicyEnforcer(m.currentTest); mock != nil && mock.unenforceMock != nil {
		return mock.unenforceMock(ip)
	}

	return nil
}

func (m *testPolicyEnforcer) GetFilterQueue() *FilterQueue {

	if mock := m.currentMocksPolicyEnforcer(m.currentTest); mock != nil && mock.getFilterQueueMock != nil {
		return mock.getFilterQueueMock()
	}

	return nil
}

func (m *testPolicyEnforcer) Start() error {

	if mock := m.currentMocksPolicyEnforcer(m.currentTest); mock != nil && mock.startMock != nil {
		return mock.startMock()
	}

	return nil
}

func (m *testPolicyEnforcer) Stop() error {

	if mock := m.currentMocksPolicyEnforcer(m.currentTest); mock != nil && mock.stopMock != nil {
		return mock.stopMock()
	}

	return nil
}

func (m *testPolicyEnforcer) currentMocksPolicyEnforcer(t *testing.T) *mockedMethodsPolicyEnforcer {
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

func (m *testPublicKeyAdder) MockPublicKeyAdd(t *testing.T, impl func(host string, cert []byte) error) {

	m.currentMocksPublicKeyAdder(t).publicKeyAddMock = impl
}

func (m *testPublicKeyAdder) PublicKeyAdd(host string, cert []byte) error {

	if mock := m.currentMocksPublicKeyAdder(m.currentTest); mock != nil && mock.publicKeyAddMock != nil {
		return mock.publicKeyAddMock(host, cert)
	}

	return nil
}

func (m *testPublicKeyAdder) currentMocksPublicKeyAdder(t *testing.T) *mockedMethodsPublicKeyAdder {
	m.lock.Lock()
	defer m.lock.Unlock()

	mocks := m.mocks[t]

	if mocks == nil {
		mocks = &mockedMethodsPublicKeyAdder{}
		m.mocks[t] = mocks
	}

	m.currentTest = t
	return mocks
}
