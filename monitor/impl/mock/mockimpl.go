// Code generated by MockGen. DO NOT EDIT.
// Source: monitor/impl/interfaces.go

// Package mockimpl is a generated GoMock package.
package mockimpl

import (
	reflect "reflect"

	collector "github.com/aporeto-inc/trireme-lib/collector"
	impl "github.com/aporeto-inc/trireme-lib/monitor/impl"
	events "github.com/aporeto-inc/trireme-lib/monitor/rpc/events"
	processor "github.com/aporeto-inc/trireme-lib/monitor/rpc/processor"
	policy "github.com/aporeto-inc/trireme-lib/policy"
	gomock "github.com/golang/mock/gomock"
)

// MockImplementation is a mock of Implementation interface
// nolint
type MockImplementation struct {
	ctrl     *gomock.Controller
	recorder *MockImplementationMockRecorder
}

// MockImplementationMockRecorder is the mock recorder for MockImplementation
// nolint
type MockImplementationMockRecorder struct {
	mock *MockImplementation
}

// NewMockImplementation creates a new mock instance
// nolint
func NewMockImplementation(ctrl *gomock.Controller) *MockImplementation {
	mock := &MockImplementation{ctrl: ctrl}
	mock.recorder = &MockImplementationMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
// nolint
func (m *MockImplementation) EXPECT() *MockImplementationMockRecorder {
	return m.recorder
}

// Start mocks base method
// nolint
func (m *MockImplementation) Start() error {
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start
// nolint
func (mr *MockImplementationMockRecorder) Start() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockImplementation)(nil).Start))
}

// Stop mocks base method
// nolint
func (m *MockImplementation) Stop() error {
	ret := m.ctrl.Call(m, "Stop")
	ret0, _ := ret[0].(error)
	return ret0
}

// Stop indicates an expected call of Stop
// nolint
func (mr *MockImplementationMockRecorder) Stop() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stop", reflect.TypeOf((*MockImplementation)(nil).Stop))
}

// SetupConfig mocks base method
// nolint
func (m *MockImplementation) SetupConfig(registerer processor.Registerer, cfg interface{}) error {
	ret := m.ctrl.Call(m, "SetupConfig", registerer, cfg)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetupConfig indicates an expected call of SetupConfig
// nolint
func (mr *MockImplementationMockRecorder) SetupConfig(registerer, cfg interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetupConfig", reflect.TypeOf((*MockImplementation)(nil).SetupConfig), registerer, cfg)
}

// SetupHandlers mocks base method
// nolint
func (m *MockImplementation) SetupHandlers(collector collector.EventCollector, puHandler impl.ProcessingUnitsHandler, syncHandler impl.SynchronizationHandler) {
	m.ctrl.Call(m, "SetupHandlers", collector, puHandler, syncHandler)
}

// SetupHandlers indicates an expected call of SetupHandlers
// nolint
func (mr *MockImplementationMockRecorder) SetupHandlers(collector, puHandler, syncHandler interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetupHandlers", reflect.TypeOf((*MockImplementation)(nil).SetupHandlers), collector, puHandler, syncHandler)
}

// MockProcessingUnitsHandler is a mock of ProcessingUnitsHandler interface
// nolint
type MockProcessingUnitsHandler struct {
	ctrl     *gomock.Controller
	recorder *MockProcessingUnitsHandlerMockRecorder
}

// MockProcessingUnitsHandlerMockRecorder is the mock recorder for MockProcessingUnitsHandler
// nolint
type MockProcessingUnitsHandlerMockRecorder struct {
	mock *MockProcessingUnitsHandler
}

// NewMockProcessingUnitsHandler creates a new mock instance
// nolint
func NewMockProcessingUnitsHandler(ctrl *gomock.Controller) *MockProcessingUnitsHandler {
	mock := &MockProcessingUnitsHandler{ctrl: ctrl}
	mock.recorder = &MockProcessingUnitsHandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
// nolint
func (m *MockProcessingUnitsHandler) EXPECT() *MockProcessingUnitsHandlerMockRecorder {
	return m.recorder
}

// CreatePURuntime mocks base method
// nolint
func (m *MockProcessingUnitsHandler) CreatePURuntime(contextID string, runtimeInfo *policy.PURuntime) error {
	ret := m.ctrl.Call(m, "CreatePURuntime", contextID, runtimeInfo)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreatePURuntime indicates an expected call of CreatePURuntime
// nolint
func (mr *MockProcessingUnitsHandlerMockRecorder) CreatePURuntime(contextID, runtimeInfo interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreatePURuntime", reflect.TypeOf((*MockProcessingUnitsHandler)(nil).CreatePURuntime), contextID, runtimeInfo)
}

// HandlePUEvent mocks base method
// nolint
func (m *MockProcessingUnitsHandler) HandlePUEvent(contextID string, event events.Event) error {
	ret := m.ctrl.Call(m, "HandlePUEvent", contextID, event)
	ret0, _ := ret[0].(error)
	return ret0
}

// HandlePUEvent indicates an expected call of HandlePUEvent
// nolint
func (mr *MockProcessingUnitsHandlerMockRecorder) HandlePUEvent(contextID, event interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandlePUEvent", reflect.TypeOf((*MockProcessingUnitsHandler)(nil).HandlePUEvent), contextID, event)
}

// MockSynchronizationHandler is a mock of SynchronizationHandler interface
// nolint
type MockSynchronizationHandler struct {
	ctrl     *gomock.Controller
	recorder *MockSynchronizationHandlerMockRecorder
}

// MockSynchronizationHandlerMockRecorder is the mock recorder for MockSynchronizationHandler
// nolint
type MockSynchronizationHandlerMockRecorder struct {
	mock *MockSynchronizationHandler
}

// NewMockSynchronizationHandler creates a new mock instance
// nolint
func NewMockSynchronizationHandler(ctrl *gomock.Controller) *MockSynchronizationHandler {
	mock := &MockSynchronizationHandler{ctrl: ctrl}
	mock.recorder = &MockSynchronizationHandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
// nolint
func (m *MockSynchronizationHandler) EXPECT() *MockSynchronizationHandlerMockRecorder {
	return m.recorder
}

// HandleSynchronization mocks base method
// nolint
func (m *MockSynchronizationHandler) HandleSynchronization(contextID string, state events.State, RuntimeReader policy.RuntimeReader, syncType events.SynchronizationType) error {
	ret := m.ctrl.Call(m, "HandleSynchronization", contextID, state, RuntimeReader, syncType)
	ret0, _ := ret[0].(error)
	return ret0
}

// HandleSynchronization indicates an expected call of HandleSynchronization
// nolint
func (mr *MockSynchronizationHandlerMockRecorder) HandleSynchronization(contextID, state, RuntimeReader, syncType interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandleSynchronization", reflect.TypeOf((*MockSynchronizationHandler)(nil).HandleSynchronization), contextID, state, RuntimeReader, syncType)
}

// HandleSynchronizationComplete mocks base method
// nolint
func (m *MockSynchronizationHandler) HandleSynchronizationComplete(syncType events.SynchronizationType) {
	m.ctrl.Call(m, "HandleSynchronizationComplete", syncType)
}

// HandleSynchronizationComplete indicates an expected call of HandleSynchronizationComplete
// nolint
func (mr *MockSynchronizationHandlerMockRecorder) HandleSynchronizationComplete(syncType interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandleSynchronizationComplete", reflect.TypeOf((*MockSynchronizationHandler)(nil).HandleSynchronizationComplete), syncType)
}
