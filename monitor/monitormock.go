package monitor

import (
	"sync"
	"testing"
)

type mockedMethods struct {
	startMock func() error
	stopMock  func() error
}

// TestMonitor us
type TestMonitor interface {
	Monitor
	MockStart(t *testing.T, impl func() error)
	MockStop(t *testing.T, impl func() error)
}

// A testManipulator is an empty TransactionalManipulator that can be easily mocked.
type testMonitor struct {
	mocks       map[*testing.T]*mockedMethods
	lock        *sync.Mutex
	currentTest *testing.T
}

// NewTestMonitor returns a new TestManipulator.
func NewTestMonitor() TestMonitor {
	return &testMonitor{
		lock:  &sync.Mutex{},
		mocks: map[*testing.T]*mockedMethods{},
	}
}

func (m *testMonitor) MockStart(t *testing.T, impl func() error) {

	m.currentMocks(t).startMock = impl
}

func (m *testMonitor) MockStop(t *testing.T, impl func() error) {

	m.currentMocks(t).stopMock = impl
}

func (m *testMonitor) Start() error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.startMock != nil {
		return mock.startMock()
	}

	return nil
}

func (m *testMonitor) Stop() error {

	if mock := m.currentMocks(m.currentTest); mock != nil && mock.stopMock != nil {
		return mock.stopMock()
	}

	return nil
}

func (m *testMonitor) currentMocks(t *testing.T) *mockedMethods {
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
