package processmon

import (
	"sync"
	"testing"

	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
)

type mockedMethods struct {
	GetExitStatusMock func(string) bool
	KillProcessMock   func(string)
	LaunchProcessMock func(string, int, string, rpcwrapper.RPCClient, string, string, string) error
	SetExitStatusMock func(string, bool) error
	SetnsNetPathMock  func(string)
}

// TestProcessManager is a mock process manager
type TestProcessManager interface {
	ProcessManager
	MockGetExitStatus(t *testing.T, impl func(string) bool)
	MockKillProcess(t *testing.T, impl func(string))
	MockLaunchProcess(t *testing.T, impl func(string, int, string, rpcwrapper.RPCClient, string, string, string) error)
	MockSetExitStatus(t *testing.T, impl func(string, bool) error)
	MockSetnsNetPath(t *testing.T, impl func(string))
}

type testProcessMon struct {
	mocks       map[*testing.T]*mockedMethods
	lock        *sync.Mutex
	currentTest *testing.T
}

// NewTestProcessMon creates a mock process manager
func NewTestProcessMon() ProcessManager {
	p := &testProcessMon{
		lock:  &sync.Mutex{},
		mocks: map[*testing.T]*mockedMethods{},
	}
	return p
}

func (m *testProcessMon) currentMocks(t *testing.T) *mockedMethods {
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
func (m *testProcessMon) MockSetnsNetPath(t *testing.T, impl func(string)) {
	m.currentMocks(t).SetnsNetPathMock = impl
}
func (m *testProcessMon) MockGetExitStatus(t *testing.T, impl func(string) bool) {
	m.currentMocks(t).GetExitStatusMock = impl
}
func (m *testProcessMon) MockKillProcess(t *testing.T, impl func(string)) {
	m.currentMocks(t).KillProcessMock = impl
}
func (m *testProcessMon) MockLaunchProcess(t *testing.T, impl func(string, int, string, rpcwrapper.RPCClient, string, string, string) error) {
	m.currentMocks(t).LaunchProcessMock = impl
}
func (m *testProcessMon) MockSetExitStatus(t *testing.T, impl func(string, bool) error) {
	m.currentMocks(t).SetExitStatusMock = impl
}

func (m *testProcessMon) SetnsNetPath(netpath string) {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.SetnsNetPathMock != nil {
		mock.SetnsNetPathMock(netpath)
		return
	}
	return
}
func (m *testProcessMon) GetExitStatus(contextID string) bool {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.GetExitStatusMock != nil {
		return mock.GetExitStatusMock(contextID)

	}
	return true
}
func (m *testProcessMon) SetExitStatus(contextID string, status bool) error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.SetExitStatusMock != nil {
		return mock.SetExitStatusMock(contextID, status)

	}
	return nil
}
func (m *testProcessMon) KillProcess(contextID string) {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.KillProcessMock != nil {
		mock.KillProcessMock(contextID)
		return
	}
}
func (m *testProcessMon) LaunchProcess(contextID string, refPid int, refNSPath string, rpchdl rpcwrapper.RPCClient, processname string, statssecret string, procMountPoint string) error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.LaunchProcessMock != nil {
		return mock.LaunchProcessMock(contextID, refPid, refNSPath, rpchdl, processname, statssecret, procMountPoint)

	}
	return nil
}
