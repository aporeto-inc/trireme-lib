package trireme

import (
	"sync"
	"testing"

	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/policy"
)

type mockedMethodsPolicyResolver struct {

	// ResolvePolicy returns the policy.PUPolicy associated with the given contextID using the given policy.RuntimeReader.
	resolvePolicyMock func(contextID string, RuntimeReader policy.RuntimeReader) (*policy.PUPolicy, error)

	// HandleDeletePU is called when a PU is removed.
	handlePUEventMock func(contextID string, eventType monitor.Event)
}

// TestPolicyResolver us
type TestPolicyResolver interface {
	PolicyResolver
	MockResolvePolicy(t *testing.T, impl func(contextID string, RuntimeReader policy.RuntimeReader) (*policy.PUPolicy, error))
	MockHandlePUEvent(t *testing.T, impl func(contextID string, eventType monitor.Event))
}

// A testPolicyResolver is an empty TransactionalManipulator that can be easily mocked.
type testPolicyResolver struct {
	mocks       map[*testing.T]*mockedMethodsPolicyResolver
	lock        *sync.Mutex
	currentTest *testing.T
}

// NewTestPolicyResolver returns a new TestManipulator.
func NewTestPolicyResolver() TestPolicyResolver {
	return &testPolicyResolver{
		lock:  &sync.Mutex{},
		mocks: map[*testing.T]*mockedMethodsPolicyResolver{},
	}
}

func (m *testPolicyResolver) MockResolvePolicy(t *testing.T, impl func(contextID string, RuntimeReader policy.RuntimeReader) (*policy.PUPolicy, error)) {

	m.currentMocks(t).resolvePolicyMock = impl
}

func (m *testPolicyResolver) MockHandlePUEvent(t *testing.T, impl func(contextID string, eventType monitor.Event)) {

	m.currentMocks(t).handlePUEventMock = impl
}

func (m *testPolicyResolver) ResolvePolicy(contextID string, RuntimeReader policy.RuntimeReader) (*policy.PUPolicy, error) {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.resolvePolicyMock != nil {
		return mock.resolvePolicyMock(contextID, RuntimeReader)
	}

	return nil, nil
}

func (m *testPolicyResolver) HandlePUEvent(contextID string, eventType monitor.Event) {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.handlePUEventMock != nil {
		mock.handlePUEventMock(contextID, eventType)
	}

}

func (m *testPolicyResolver) currentMocks(t *testing.T) *mockedMethodsPolicyResolver {
	m.lock.Lock()
	defer m.lock.Unlock()

	mocks := m.mocks[t]

	if mocks == nil {
		mocks = &mockedMethodsPolicyResolver{}
		m.mocks[t] = mocks
	}

	m.currentTest = t
	return mocks
}
