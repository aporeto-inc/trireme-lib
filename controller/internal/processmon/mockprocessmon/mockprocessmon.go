// Code generated by MockGen. DO NOT EDIT.
// Source: controller/internal/processmon/interfaces.go

// Package mockprocessmon is a generated GoMock package.
package mockprocessmon

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	rpcwrapper "go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	claimsheader "go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	policy "go.aporeto.io/trireme-lib/policy"
)

// MockProcessManager is a mock of ProcessManager interface
// nolint
type MockProcessManager struct {
	ctrl     *gomock.Controller
	recorder *MockProcessManagerMockRecorder
}

// MockProcessManagerMockRecorder is the mock recorder for MockProcessManager
// nolint
type MockProcessManagerMockRecorder struct {
	mock *MockProcessManager
}

// NewMockProcessManager creates a new mock instance
// nolint
func NewMockProcessManager(ctrl *gomock.Controller) *MockProcessManager {
	mock := &MockProcessManager{ctrl: ctrl}
	mock.recorder = &MockProcessManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
// nolint
func (m *MockProcessManager) EXPECT() *MockProcessManagerMockRecorder {
	return m.recorder
}

// KillProcess mocks base method
// nolint
func (m *MockProcessManager) KillProcess(contextID string) {
	m.ctrl.Call(m, "KillProcess", contextID)
}

// KillProcess indicates an expected call of KillProcess
// nolint
func (mr *MockProcessManagerMockRecorder) KillProcess(contextID interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "KillProcess", reflect.TypeOf((*MockProcessManager)(nil).KillProcess), contextID)
}

// LaunchProcess mocks base method
// nolint
func (m *MockProcessManager) LaunchProcess(contextID string, refPid int, refNsPath string, rpchdl rpcwrapper.RPCClient, arg, statssecret, procMountPoint string) (bool, error) {
	ret := m.ctrl.Call(m, "LaunchProcess", contextID, refPid, refNsPath, rpchdl, arg, statssecret, procMountPoint)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LaunchProcess indicates an expected call of LaunchProcess
// nolint
func (mr *MockProcessManagerMockRecorder) LaunchProcess(contextID, refPid, refNsPath, rpchdl, arg, statssecret, procMountPoint interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LaunchProcess", reflect.TypeOf((*MockProcessManager)(nil).LaunchProcess), contextID, refPid, refNsPath, rpchdl, arg, statssecret, procMountPoint)
}

// SetLogParameters mocks base method
// nolint
func (m *MockProcessManager) SetLogParameters(logToConsole, logWithID bool, logLevel, logFormat string, compressedTags claimsheader.CompressionType) {
	m.ctrl.Call(m, "SetLogParameters", logToConsole, logWithID, logLevel, logFormat, compressedTags)
}

// SetLogParameters indicates an expected call of SetLogParameters
// nolint
func (mr *MockProcessManagerMockRecorder) SetLogParameters(logToConsole, logWithID, logLevel, logFormat, compressedTags interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetLogParameters", reflect.TypeOf((*MockProcessManager)(nil).SetLogParameters), logToConsole, logWithID, logLevel, logFormat, compressedTags)
}

// SetRuntimeErrorChannel mocks base method
// nolint
func (m *MockProcessManager) SetRuntimeErrorChannel(e chan *policy.RuntimeError) {
	m.ctrl.Call(m, "SetRuntimeErrorChannel", e)
}

// SetRuntimeErrorChannel indicates an expected call of SetRuntimeErrorChannel
// nolint
func (mr *MockProcessManagerMockRecorder) SetRuntimeErrorChannel(e interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetRuntimeErrorChannel", reflect.TypeOf((*MockProcessManager)(nil).SetRuntimeErrorChannel), e)
}
