// Code generated by MockGen. DO NOT EDIT.
// Source: go.aporeto.io/enforcerd/trireme-lib/utils/cri (interfaces: ExtendedRuntimeService)

// Package mockcri is a generated GoMock package.
package mockcri

import (
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	v1alpha2 "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

// MockExtendedRuntimeService is a mock of ExtendedRuntimeService interface
// nolint
type MockExtendedRuntimeService struct {
	ctrl     *gomock.Controller
	recorder *MockExtendedRuntimeServiceMockRecorder
}

// MockExtendedRuntimeServiceMockRecorder is the mock recorder for MockExtendedRuntimeService
// nolint
type MockExtendedRuntimeServiceMockRecorder struct {
	mock *MockExtendedRuntimeService
}

// NewMockExtendedRuntimeService creates a new mock instance
// nolint
func NewMockExtendedRuntimeService(ctrl *gomock.Controller) *MockExtendedRuntimeService {
	mock := &MockExtendedRuntimeService{ctrl: ctrl}
	mock.recorder = &MockExtendedRuntimeServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
// nolint
func (m *MockExtendedRuntimeService) EXPECT() *MockExtendedRuntimeServiceMockRecorder {
	return m.recorder
}

// Attach mocks base method
// nolint
func (m *MockExtendedRuntimeService) Attach(arg0 *v1alpha2.AttachRequest) (*v1alpha2.AttachResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Attach", arg0)
	ret0, _ := ret[0].(*v1alpha2.AttachResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Attach indicates an expected call of Attach
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) Attach(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Attach", reflect.TypeOf((*MockExtendedRuntimeService)(nil).Attach), arg0)
}

// ContainerStats mocks base method
// nolint
func (m *MockExtendedRuntimeService) ContainerStats(arg0 string) (*v1alpha2.ContainerStats, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ContainerStats", arg0)
	ret0, _ := ret[0].(*v1alpha2.ContainerStats)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ContainerStats indicates an expected call of ContainerStats
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) ContainerStats(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ContainerStats", reflect.TypeOf((*MockExtendedRuntimeService)(nil).ContainerStats), arg0)
}

// ContainerStatus mocks base method
// nolint
func (m *MockExtendedRuntimeService) ContainerStatus(arg0 string) (*v1alpha2.ContainerStatus, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ContainerStatus", arg0)
	ret0, _ := ret[0].(*v1alpha2.ContainerStatus)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ContainerStatus indicates an expected call of ContainerStatus
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) ContainerStatus(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ContainerStatus", reflect.TypeOf((*MockExtendedRuntimeService)(nil).ContainerStatus), arg0)
}

// ContainerStatusVerbose mocks base method
// nolint
func (m *MockExtendedRuntimeService) ContainerStatusVerbose(arg0 string) (*v1alpha2.ContainerStatus, map[string]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ContainerStatusVerbose", arg0)
	ret0, _ := ret[0].(*v1alpha2.ContainerStatus)
	ret1, _ := ret[1].(map[string]string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ContainerStatusVerbose indicates an expected call of ContainerStatusVerbose
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) ContainerStatusVerbose(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ContainerStatusVerbose", reflect.TypeOf((*MockExtendedRuntimeService)(nil).ContainerStatusVerbose), arg0)
}

// CreateContainer mocks base method
// nolint
func (m *MockExtendedRuntimeService) CreateContainer(arg0 string, arg1 *v1alpha2.ContainerConfig, arg2 *v1alpha2.PodSandboxConfig) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateContainer", arg0, arg1, arg2)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateContainer indicates an expected call of CreateContainer
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) CreateContainer(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateContainer", reflect.TypeOf((*MockExtendedRuntimeService)(nil).CreateContainer), arg0, arg1, arg2)
}

// Exec mocks base method
// nolint
func (m *MockExtendedRuntimeService) Exec(arg0 *v1alpha2.ExecRequest) (*v1alpha2.ExecResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Exec", arg0)
	ret0, _ := ret[0].(*v1alpha2.ExecResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Exec indicates an expected call of Exec
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) Exec(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Exec", reflect.TypeOf((*MockExtendedRuntimeService)(nil).Exec), arg0)
}

// ExecSync mocks base method
// nolint
func (m *MockExtendedRuntimeService) ExecSync(arg0 string, arg1 []string, arg2 time.Duration) ([]byte, []byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExecSync", arg0, arg1, arg2)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].([]byte)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ExecSync indicates an expected call of ExecSync
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) ExecSync(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExecSync", reflect.TypeOf((*MockExtendedRuntimeService)(nil).ExecSync), arg0, arg1, arg2)
}

// ListContainerStats mocks base method
// nolint
func (m *MockExtendedRuntimeService) ListContainerStats(arg0 *v1alpha2.ContainerStatsFilter) ([]*v1alpha2.ContainerStats, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListContainerStats", arg0)
	ret0, _ := ret[0].([]*v1alpha2.ContainerStats)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListContainerStats indicates an expected call of ListContainerStats
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) ListContainerStats(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListContainerStats", reflect.TypeOf((*MockExtendedRuntimeService)(nil).ListContainerStats), arg0)
}

// ListContainers mocks base method
// nolint
func (m *MockExtendedRuntimeService) ListContainers(arg0 *v1alpha2.ContainerFilter) ([]*v1alpha2.Container, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListContainers", arg0)
	ret0, _ := ret[0].([]*v1alpha2.Container)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListContainers indicates an expected call of ListContainers
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) ListContainers(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListContainers", reflect.TypeOf((*MockExtendedRuntimeService)(nil).ListContainers), arg0)
}

// ListPodSandbox mocks base method
// nolint
func (m *MockExtendedRuntimeService) ListPodSandbox(arg0 *v1alpha2.PodSandboxFilter) ([]*v1alpha2.PodSandbox, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListPodSandbox", arg0)
	ret0, _ := ret[0].([]*v1alpha2.PodSandbox)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListPodSandbox indicates an expected call of ListPodSandbox
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) ListPodSandbox(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListPodSandbox", reflect.TypeOf((*MockExtendedRuntimeService)(nil).ListPodSandbox), arg0)
}

// PodSandboxStatus mocks base method
// nolint
func (m *MockExtendedRuntimeService) PodSandboxStatus(arg0 string) (*v1alpha2.PodSandboxStatus, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PodSandboxStatus", arg0)
	ret0, _ := ret[0].(*v1alpha2.PodSandboxStatus)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PodSandboxStatus indicates an expected call of PodSandboxStatus
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) PodSandboxStatus(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PodSandboxStatus", reflect.TypeOf((*MockExtendedRuntimeService)(nil).PodSandboxStatus), arg0)
}

// PodSandboxStatusVerbose mocks base method
// nolint
func (m *MockExtendedRuntimeService) PodSandboxStatusVerbose(arg0 string) (*v1alpha2.PodSandboxStatus, map[string]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PodSandboxStatusVerbose", arg0)
	ret0, _ := ret[0].(*v1alpha2.PodSandboxStatus)
	ret1, _ := ret[1].(map[string]string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// PodSandboxStatusVerbose indicates an expected call of PodSandboxStatusVerbose
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) PodSandboxStatusVerbose(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PodSandboxStatusVerbose", reflect.TypeOf((*MockExtendedRuntimeService)(nil).PodSandboxStatusVerbose), arg0)
}

// PortForward mocks base method
// nolint
func (m *MockExtendedRuntimeService) PortForward(arg0 *v1alpha2.PortForwardRequest) (*v1alpha2.PortForwardResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PortForward", arg0)
	ret0, _ := ret[0].(*v1alpha2.PortForwardResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PortForward indicates an expected call of PortForward
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) PortForward(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PortForward", reflect.TypeOf((*MockExtendedRuntimeService)(nil).PortForward), arg0)
}

// RemoveContainer mocks base method
// nolint
func (m *MockExtendedRuntimeService) RemoveContainer(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoveContainer", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// RemoveContainer indicates an expected call of RemoveContainer
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) RemoveContainer(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveContainer", reflect.TypeOf((*MockExtendedRuntimeService)(nil).RemoveContainer), arg0)
}

// RemovePodSandbox mocks base method
// nolint
func (m *MockExtendedRuntimeService) RemovePodSandbox(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemovePodSandbox", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// RemovePodSandbox indicates an expected call of RemovePodSandbox
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) RemovePodSandbox(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemovePodSandbox", reflect.TypeOf((*MockExtendedRuntimeService)(nil).RemovePodSandbox), arg0)
}

// ReopenContainerLog mocks base method
// nolint
func (m *MockExtendedRuntimeService) ReopenContainerLog(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReopenContainerLog", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// ReopenContainerLog indicates an expected call of ReopenContainerLog
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) ReopenContainerLog(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReopenContainerLog", reflect.TypeOf((*MockExtendedRuntimeService)(nil).ReopenContainerLog), arg0)
}

// RunPodSandbox mocks base method
// nolint
func (m *MockExtendedRuntimeService) RunPodSandbox(arg0 *v1alpha2.PodSandboxConfig, arg1 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RunPodSandbox", arg0, arg1)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RunPodSandbox indicates an expected call of RunPodSandbox
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) RunPodSandbox(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RunPodSandbox", reflect.TypeOf((*MockExtendedRuntimeService)(nil).RunPodSandbox), arg0, arg1)
}

// StartContainer mocks base method
// nolint
func (m *MockExtendedRuntimeService) StartContainer(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StartContainer", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// StartContainer indicates an expected call of StartContainer
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) StartContainer(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StartContainer", reflect.TypeOf((*MockExtendedRuntimeService)(nil).StartContainer), arg0)
}

// Status mocks base method
// nolint
func (m *MockExtendedRuntimeService) Status() (*v1alpha2.RuntimeStatus, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Status")
	ret0, _ := ret[0].(*v1alpha2.RuntimeStatus)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Status indicates an expected call of Status
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) Status() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Status", reflect.TypeOf((*MockExtendedRuntimeService)(nil).Status))
}

// StatusVerbose mocks base method
// nolint
func (m *MockExtendedRuntimeService) StatusVerbose() (*v1alpha2.RuntimeStatus, map[string]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StatusVerbose")
	ret0, _ := ret[0].(*v1alpha2.RuntimeStatus)
	ret1, _ := ret[1].(map[string]string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// StatusVerbose indicates an expected call of StatusVerbose
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) StatusVerbose() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StatusVerbose", reflect.TypeOf((*MockExtendedRuntimeService)(nil).StatusVerbose))
}

// StopContainer mocks base method
// nolint
func (m *MockExtendedRuntimeService) StopContainer(arg0 string, arg1 int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StopContainer", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// StopContainer indicates an expected call of StopContainer
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) StopContainer(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StopContainer", reflect.TypeOf((*MockExtendedRuntimeService)(nil).StopContainer), arg0, arg1)
}

// StopPodSandbox mocks base method
// nolint
func (m *MockExtendedRuntimeService) StopPodSandbox(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StopPodSandbox", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// StopPodSandbox indicates an expected call of StopPodSandbox
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) StopPodSandbox(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StopPodSandbox", reflect.TypeOf((*MockExtendedRuntimeService)(nil).StopPodSandbox), arg0)
}

// UpdateContainerResources mocks base method
// nolint
func (m *MockExtendedRuntimeService) UpdateContainerResources(arg0 string, arg1 *v1alpha2.LinuxContainerResources) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateContainerResources", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateContainerResources indicates an expected call of UpdateContainerResources
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) UpdateContainerResources(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateContainerResources", reflect.TypeOf((*MockExtendedRuntimeService)(nil).UpdateContainerResources), arg0, arg1)
}

// UpdateRuntimeConfig mocks base method
// nolint
func (m *MockExtendedRuntimeService) UpdateRuntimeConfig(arg0 *v1alpha2.RuntimeConfig) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateRuntimeConfig", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateRuntimeConfig indicates an expected call of UpdateRuntimeConfig
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) UpdateRuntimeConfig(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateRuntimeConfig", reflect.TypeOf((*MockExtendedRuntimeService)(nil).UpdateRuntimeConfig), arg0)
}

// Version mocks base method
// nolint
func (m *MockExtendedRuntimeService) Version(arg0 string) (*v1alpha2.VersionResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Version", arg0)
	ret0, _ := ret[0].(*v1alpha2.VersionResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Version indicates an expected call of Version
// nolint
func (mr *MockExtendedRuntimeServiceMockRecorder) Version(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Version", reflect.TypeOf((*MockExtendedRuntimeService)(nil).Version), arg0)
}
