// Code generated by MockGen. DO NOT EDIT.
// Source: k8s.io/client-go/kubernetes/typed/core/v1 (interfaces: CoreV1Interface,PodInterface)

// Package podmonitor is a generated GoMock package.
package podmonitor

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	v1 "k8s.io/api/core/v1"
	v1beta1 "k8s.io/api/policy/v1beta1"
	v10 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	v11 "k8s.io/client-go/kubernetes/typed/core/v1"
	rest "k8s.io/client-go/rest"
)

// MockCoreV1Interface is a mock of CoreV1Interface interface
// nolint
type MockCoreV1Interface struct {
	ctrl     *gomock.Controller
	recorder *MockCoreV1InterfaceMockRecorder
}

// MockCoreV1InterfaceMockRecorder is the mock recorder for MockCoreV1Interface
// nolint
type MockCoreV1InterfaceMockRecorder struct {
	mock *MockCoreV1Interface
}

// NewMockCoreV1Interface creates a new mock instance
// nolint
func NewMockCoreV1Interface(ctrl *gomock.Controller) *MockCoreV1Interface {
	mock := &MockCoreV1Interface{ctrl: ctrl}
	mock.recorder = &MockCoreV1InterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
// nolint
func (m *MockCoreV1Interface) EXPECT() *MockCoreV1InterfaceMockRecorder {
	return m.recorder
}

// ComponentStatuses mocks base method
// nolint
func (m *MockCoreV1Interface) ComponentStatuses() v11.ComponentStatusInterface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ComponentStatuses")
	ret0, _ := ret[0].(v11.ComponentStatusInterface)
	return ret0
}

// ComponentStatuses indicates an expected call of ComponentStatuses
// nolint
func (mr *MockCoreV1InterfaceMockRecorder) ComponentStatuses() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ComponentStatuses", reflect.TypeOf((*MockCoreV1Interface)(nil).ComponentStatuses))
}

// ConfigMaps mocks base method
// nolint
func (m *MockCoreV1Interface) ConfigMaps(arg0 string) v11.ConfigMapInterface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConfigMaps", arg0)
	ret0, _ := ret[0].(v11.ConfigMapInterface)
	return ret0
}

// ConfigMaps indicates an expected call of ConfigMaps
// nolint
func (mr *MockCoreV1InterfaceMockRecorder) ConfigMaps(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConfigMaps", reflect.TypeOf((*MockCoreV1Interface)(nil).ConfigMaps), arg0)
}

// Endpoints mocks base method
// nolint
func (m *MockCoreV1Interface) Endpoints(arg0 string) v11.EndpointsInterface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Endpoints", arg0)
	ret0, _ := ret[0].(v11.EndpointsInterface)
	return ret0
}

// Endpoints indicates an expected call of Endpoints
// nolint
func (mr *MockCoreV1InterfaceMockRecorder) Endpoints(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Endpoints", reflect.TypeOf((*MockCoreV1Interface)(nil).Endpoints), arg0)
}

// Events mocks base method
// nolint
func (m *MockCoreV1Interface) Events(arg0 string) v11.EventInterface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Events", arg0)
	ret0, _ := ret[0].(v11.EventInterface)
	return ret0
}

// Events indicates an expected call of Events
// nolint
func (mr *MockCoreV1InterfaceMockRecorder) Events(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Events", reflect.TypeOf((*MockCoreV1Interface)(nil).Events), arg0)
}

// LimitRanges mocks base method
// nolint
func (m *MockCoreV1Interface) LimitRanges(arg0 string) v11.LimitRangeInterface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LimitRanges", arg0)
	ret0, _ := ret[0].(v11.LimitRangeInterface)
	return ret0
}

// LimitRanges indicates an expected call of LimitRanges
// nolint
func (mr *MockCoreV1InterfaceMockRecorder) LimitRanges(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LimitRanges", reflect.TypeOf((*MockCoreV1Interface)(nil).LimitRanges), arg0)
}

// Namespaces mocks base method
// nolint
func (m *MockCoreV1Interface) Namespaces() v11.NamespaceInterface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Namespaces")
	ret0, _ := ret[0].(v11.NamespaceInterface)
	return ret0
}

// Namespaces indicates an expected call of Namespaces
// nolint
func (mr *MockCoreV1InterfaceMockRecorder) Namespaces() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Namespaces", reflect.TypeOf((*MockCoreV1Interface)(nil).Namespaces))
}

// Nodes mocks base method
// nolint
func (m *MockCoreV1Interface) Nodes() v11.NodeInterface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Nodes")
	ret0, _ := ret[0].(v11.NodeInterface)
	return ret0
}

// Nodes indicates an expected call of Nodes
// nolint
func (mr *MockCoreV1InterfaceMockRecorder) Nodes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Nodes", reflect.TypeOf((*MockCoreV1Interface)(nil).Nodes))
}

// PersistentVolumeClaims mocks base method
// nolint
func (m *MockCoreV1Interface) PersistentVolumeClaims(arg0 string) v11.PersistentVolumeClaimInterface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PersistentVolumeClaims", arg0)
	ret0, _ := ret[0].(v11.PersistentVolumeClaimInterface)
	return ret0
}

// PersistentVolumeClaims indicates an expected call of PersistentVolumeClaims
// nolint
func (mr *MockCoreV1InterfaceMockRecorder) PersistentVolumeClaims(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PersistentVolumeClaims", reflect.TypeOf((*MockCoreV1Interface)(nil).PersistentVolumeClaims), arg0)
}

// PersistentVolumes mocks base method
// nolint
func (m *MockCoreV1Interface) PersistentVolumes() v11.PersistentVolumeInterface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PersistentVolumes")
	ret0, _ := ret[0].(v11.PersistentVolumeInterface)
	return ret0
}

// PersistentVolumes indicates an expected call of PersistentVolumes
// nolint
func (mr *MockCoreV1InterfaceMockRecorder) PersistentVolumes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PersistentVolumes", reflect.TypeOf((*MockCoreV1Interface)(nil).PersistentVolumes))
}

// PodTemplates mocks base method
// nolint
func (m *MockCoreV1Interface) PodTemplates(arg0 string) v11.PodTemplateInterface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PodTemplates", arg0)
	ret0, _ := ret[0].(v11.PodTemplateInterface)
	return ret0
}

// PodTemplates indicates an expected call of PodTemplates
// nolint
func (mr *MockCoreV1InterfaceMockRecorder) PodTemplates(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PodTemplates", reflect.TypeOf((*MockCoreV1Interface)(nil).PodTemplates), arg0)
}

// Pods mocks base method
// nolint
func (m *MockCoreV1Interface) Pods(arg0 string) v11.PodInterface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Pods", arg0)
	ret0, _ := ret[0].(v11.PodInterface)
	return ret0
}

// Pods indicates an expected call of Pods
// nolint
func (mr *MockCoreV1InterfaceMockRecorder) Pods(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Pods", reflect.TypeOf((*MockCoreV1Interface)(nil).Pods), arg0)
}

// RESTClient mocks base method
// nolint
func (m *MockCoreV1Interface) RESTClient() rest.Interface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RESTClient")
	ret0, _ := ret[0].(rest.Interface)
	return ret0
}

// RESTClient indicates an expected call of RESTClient
// nolint
func (mr *MockCoreV1InterfaceMockRecorder) RESTClient() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RESTClient", reflect.TypeOf((*MockCoreV1Interface)(nil).RESTClient))
}

// ReplicationControllers mocks base method
// nolint
func (m *MockCoreV1Interface) ReplicationControllers(arg0 string) v11.ReplicationControllerInterface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReplicationControllers", arg0)
	ret0, _ := ret[0].(v11.ReplicationControllerInterface)
	return ret0
}

// ReplicationControllers indicates an expected call of ReplicationControllers
// nolint
func (mr *MockCoreV1InterfaceMockRecorder) ReplicationControllers(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReplicationControllers", reflect.TypeOf((*MockCoreV1Interface)(nil).ReplicationControllers), arg0)
}

// ResourceQuotas mocks base method
// nolint
func (m *MockCoreV1Interface) ResourceQuotas(arg0 string) v11.ResourceQuotaInterface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResourceQuotas", arg0)
	ret0, _ := ret[0].(v11.ResourceQuotaInterface)
	return ret0
}

// ResourceQuotas indicates an expected call of ResourceQuotas
// nolint
func (mr *MockCoreV1InterfaceMockRecorder) ResourceQuotas(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResourceQuotas", reflect.TypeOf((*MockCoreV1Interface)(nil).ResourceQuotas), arg0)
}

// Secrets mocks base method
// nolint
func (m *MockCoreV1Interface) Secrets(arg0 string) v11.SecretInterface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Secrets", arg0)
	ret0, _ := ret[0].(v11.SecretInterface)
	return ret0
}

// Secrets indicates an expected call of Secrets
// nolint
func (mr *MockCoreV1InterfaceMockRecorder) Secrets(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Secrets", reflect.TypeOf((*MockCoreV1Interface)(nil).Secrets), arg0)
}

// ServiceAccounts mocks base method
// nolint
func (m *MockCoreV1Interface) ServiceAccounts(arg0 string) v11.ServiceAccountInterface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ServiceAccounts", arg0)
	ret0, _ := ret[0].(v11.ServiceAccountInterface)
	return ret0
}

// ServiceAccounts indicates an expected call of ServiceAccounts
// nolint
func (mr *MockCoreV1InterfaceMockRecorder) ServiceAccounts(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ServiceAccounts", reflect.TypeOf((*MockCoreV1Interface)(nil).ServiceAccounts), arg0)
}

// Services mocks base method
// nolint
func (m *MockCoreV1Interface) Services(arg0 string) v11.ServiceInterface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Services", arg0)
	ret0, _ := ret[0].(v11.ServiceInterface)
	return ret0
}

// Services indicates an expected call of Services
// nolint
func (mr *MockCoreV1InterfaceMockRecorder) Services(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Services", reflect.TypeOf((*MockCoreV1Interface)(nil).Services), arg0)
}

// MockPodInterface is a mock of PodInterface interface
// nolint
type MockPodInterface struct {
	ctrl     *gomock.Controller
	recorder *MockPodInterfaceMockRecorder
}

// MockPodInterfaceMockRecorder is the mock recorder for MockPodInterface
// nolint
type MockPodInterfaceMockRecorder struct {
	mock *MockPodInterface
}

// NewMockPodInterface creates a new mock instance
// nolint
func NewMockPodInterface(ctrl *gomock.Controller) *MockPodInterface {
	mock := &MockPodInterface{ctrl: ctrl}
	mock.recorder = &MockPodInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
// nolint
func (m *MockPodInterface) EXPECT() *MockPodInterfaceMockRecorder {
	return m.recorder
}

// Bind mocks base method
// nolint
func (m *MockPodInterface) Bind(arg0 *v1.Binding) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Bind", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Bind indicates an expected call of Bind
// nolint
func (mr *MockPodInterfaceMockRecorder) Bind(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Bind", reflect.TypeOf((*MockPodInterface)(nil).Bind), arg0)
}

// Create mocks base method
// nolint
func (m *MockPodInterface) Create(arg0 *v1.Pod) (*v1.Pod, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", arg0)
	ret0, _ := ret[0].(*v1.Pod)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Create indicates an expected call of Create
// nolint
func (mr *MockPodInterfaceMockRecorder) Create(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockPodInterface)(nil).Create), arg0)
}

// Delete mocks base method
// nolint
func (m *MockPodInterface) Delete(arg0 string, arg1 *v10.DeleteOptions) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete
// nolint
func (mr *MockPodInterfaceMockRecorder) Delete(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockPodInterface)(nil).Delete), arg0, arg1)
}

// DeleteCollection mocks base method
// nolint
func (m *MockPodInterface) DeleteCollection(arg0 *v10.DeleteOptions, arg1 v10.ListOptions) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteCollection", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteCollection indicates an expected call of DeleteCollection
// nolint
func (mr *MockPodInterfaceMockRecorder) DeleteCollection(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteCollection", reflect.TypeOf((*MockPodInterface)(nil).DeleteCollection), arg0, arg1)
}

// Evict mocks base method
// nolint
func (m *MockPodInterface) Evict(arg0 *v1beta1.Eviction) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Evict", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Evict indicates an expected call of Evict
// nolint
func (mr *MockPodInterfaceMockRecorder) Evict(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Evict", reflect.TypeOf((*MockPodInterface)(nil).Evict), arg0)
}

// Get mocks base method
// nolint
func (m *MockPodInterface) Get(arg0 string, arg1 v10.GetOptions) (*v1.Pod, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", arg0, arg1)
	ret0, _ := ret[0].(*v1.Pod)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get
// nolint
func (mr *MockPodInterfaceMockRecorder) Get(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockPodInterface)(nil).Get), arg0, arg1)
}

// GetLogs mocks base method
// nolint
func (m *MockPodInterface) GetLogs(arg0 string, arg1 *v1.PodLogOptions) *rest.Request {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLogs", arg0, arg1)
	ret0, _ := ret[0].(*rest.Request)
	return ret0
}

// GetLogs indicates an expected call of GetLogs
// nolint
func (mr *MockPodInterfaceMockRecorder) GetLogs(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLogs", reflect.TypeOf((*MockPodInterface)(nil).GetLogs), arg0, arg1)
}

// List mocks base method
// nolint
func (m *MockPodInterface) List(arg0 v10.ListOptions) (*v1.PodList, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", arg0)
	ret0, _ := ret[0].(*v1.PodList)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List
// nolint
func (mr *MockPodInterfaceMockRecorder) List(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockPodInterface)(nil).List), arg0)
}

// Patch mocks base method
// nolint
func (m *MockPodInterface) Patch(arg0 string, arg1 types.PatchType, arg2 []byte, arg3 ...string) (*v1.Pod, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1, arg2}
	for _, a := range arg3 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Patch", varargs...)
	ret0, _ := ret[0].(*v1.Pod)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Patch indicates an expected call of Patch
// nolint
func (mr *MockPodInterfaceMockRecorder) Patch(arg0, arg1, arg2 interface{}, arg3 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1, arg2}, arg3...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Patch", reflect.TypeOf((*MockPodInterface)(nil).Patch), varargs...)
}

// Update mocks base method
// nolint
func (m *MockPodInterface) Update(arg0 *v1.Pod) (*v1.Pod, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", arg0)
	ret0, _ := ret[0].(*v1.Pod)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Update indicates an expected call of Update
// nolint
func (mr *MockPodInterfaceMockRecorder) Update(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockPodInterface)(nil).Update), arg0)
}

// UpdateStatus mocks base method
// nolint
func (m *MockPodInterface) UpdateStatus(arg0 *v1.Pod) (*v1.Pod, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateStatus", arg0)
	ret0, _ := ret[0].(*v1.Pod)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateStatus indicates an expected call of UpdateStatus
// nolint
func (mr *MockPodInterfaceMockRecorder) UpdateStatus(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateStatus", reflect.TypeOf((*MockPodInterface)(nil).UpdateStatus), arg0)
}

// Watch mocks base method
// nolint
func (m *MockPodInterface) Watch(arg0 v10.ListOptions) (watch.Interface, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Watch", arg0)
	ret0, _ := ret[0].(watch.Interface)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Watch indicates an expected call of Watch
// nolint
func (mr *MockPodInterfaceMockRecorder) Watch(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Watch", reflect.TypeOf((*MockPodInterface)(nil).Watch), arg0)
}
