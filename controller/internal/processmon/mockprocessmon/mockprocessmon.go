// Code generated by MockGen. DO NOT EDIT.
// Source: controller/internal/processmon/interfaces.go

// Package mockprocessmon is a generated GoMock package.
package mockprocessmon

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
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

// KillRemoteEnforcer mocks base method
// nolint
func (m *MockProcessManager) KillRemoteEnforcer(contextID string, force bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "KillRemoteEnforcer", contextID, force)
	ret0, _ := ret[0].(error)
	return ret0
}

// KillRemoteEnforcer indicates an expected call of KillRemoteEnforcer
// nolint
func (mr *MockProcessManagerMockRecorder) KillRemoteEnforcer(contextID, force interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "KillRemoteEnforcer", reflect.TypeOf((*MockProcessManager)(nil).KillRemoteEnforcer), contextID, force)
}

// LaunchRemoteEnforcer mocks base method
// nolint
func (m *MockProcessManager) LaunchRemoteEnforcer(contextID string, refPid int, refNsPath, arg, statssecret, procMountPoint string, enforcerType policy.EnforcerType) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LaunchRemoteEnforcer", contextID, refPid, refNsPath, arg, statssecret, procMountPoint, enforcerType)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LaunchRemoteEnforcer indicates an expected call of LaunchRemoteEnforcer
// nolint
func (mr *MockProcessManagerMockRecorder) LaunchRemoteEnforcer(contextID, refPid, refNsPath, arg, statssecret, procMountPoint, enforcerType interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LaunchRemoteEnforcer", reflect.TypeOf((*MockProcessManager)(nil).LaunchRemoteEnforcer), contextID, refPid, refNsPath, arg, statssecret, procMountPoint, enforcerType)
}
