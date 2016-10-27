package trireme

import (
	"sync"
	"testing"

	"github.com/aporeto-inc/trireme/policy"
)

type mockedMethodsPolicyResolver struct {

	// ResolvePolicy returns the policy.PUPolicy associated with the given contextID using the given policy.RuntimeReader.
	resolvePolicyMock func(contextID string, RuntimeReader policy.RuntimeReader) (*policy.PUPolicy, error)

	// HandleDeletePU is called when a PU is removed.
	handleDeletePUMock func(contextID string) error

	// HandleDeletePU is called when a PU is removed.
	handleDestroyPUMock func(contextID string) error

	// SetPolicyUpdater sets the PolicyUpdater to use by the PolicyResolver.
	setPolicyUpdaterMock func(p PolicyUpdater) error
}

// TestPolicyResolver us
type TestPolicyResolver interface {
	PolicyResolver
	MockResolvePolicy(t *testing.T, impl func(contextID string, RuntimeReader policy.RuntimeReader) (*policy.PUPolicy, error))
	MockHandleDeletePU(t *testing.T, impl func(contextID string) error)
	MockHandleDestroyPU(t *testing.T, impl func(contextID string) error)
	MockSetPolicyUpdater(t *testing.T, impl func(p PolicyUpdater) error)
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

func (m *testPolicyResolver) MockHandleDeletePU(t *testing.T, impl func(contextID string) error) {

	m.currentMocks(t).handleDeletePUMock = impl
}

func (m *testPolicyResolver) MockHandleDestroyPU(t *testing.T, impl func(contextID string) error) {

	m.currentMocks(t).handleDestroyPUMock = impl
}

func (m *testPolicyResolver) MockSetPolicyUpdater(t *testing.T, impl func(p PolicyUpdater) error) {

	m.currentMocks(t).setPolicyUpdaterMock = impl
}

func (m *testPolicyResolver) ResolvePolicy(contextID string, RuntimeReader policy.RuntimeReader) (*policy.PUPolicy, error) {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.resolvePolicyMock != nil {
		return mock.resolvePolicyMock(contextID, RuntimeReader)
	}

	return nil, nil
}

func (m *testPolicyResolver) HandleDeletePU(contextID string) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.handleDeletePUMock != nil {
		return mock.handleDeletePUMock(contextID)
	}

	return nil
}

func (m *testPolicyResolver) HandleDestroyPU(contextID string) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.handleDestroyPUMock != nil {
		return mock.handleDestroyPUMock(contextID)
	}

	return nil
}

func (m *testPolicyResolver) SetPolicyUpdater(p PolicyUpdater) error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.setPolicyUpdaterMock != nil {
		return mock.setPolicyUpdaterMock(p)
	}

	return nil
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
