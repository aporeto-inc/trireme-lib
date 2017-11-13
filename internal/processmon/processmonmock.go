package processmon

import (
	"sync"
	"testing"

	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
)

type mockedMethods struct {
	KillProcessMock            func(string)
	LaunchProcessMock          func(string, int, string, rpcwrapper.RPCClient, string, string, string) error
	SetupLogAndProcessArgsMock func(bool, []string)
}

// TestProcessManager is a mock process manager
type TestProcessManager interface {
	ProcessManager
	MockKillProcess(t *testing.T, impl func(string))
	MockLaunchProcess(t *testing.T, impl func(string, int, string, rpcwrapper.RPCClient, string, string, string) error)
	MockSetupLogAndProcessArgs(t *testing.T, impl func(bool, []string))
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
func (m *testProcessMon) MockKillProcess(t *testing.T, impl func(string)) {
	m.currentMocks(t).KillProcessMock = impl
}
func (m *testProcessMon) MockLaunchProcess(t *testing.T, impl func(string, int, string, rpcwrapper.RPCClient, string, string, string) error) {
	m.currentMocks(t).LaunchProcessMock = impl
}
func (m *testProcessMon) MockSetupLogAndProcessArgs(t *testing.T, impl func(bool, []string)) {
	m.currentMocks(t).SetupLogAndProcessArgsMock = impl
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
func (m *testProcessMon) SetupLogAndProcessArgs(logToConsole bool, args []string) {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.LaunchProcessMock != nil {
		mock.SetupLogAndProcessArgsMock(logToConsole, args)
	}
}
