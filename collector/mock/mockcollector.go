// Code generated by MockGen. DO NOT EDIT.
// Source: collector/interfaces.go

// Package mockcollector is a generated GoMock package.
package mockcollector

import (
	collector "github.com/aporeto-inc/trireme/collector"
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
)

// MockEventCollector is a mock of EventCollector interface
type MockEventCollector struct {
	ctrl     *gomock.Controller
	recorder *MockEventCollectorMockRecorder
}

// MockEventCollectorMockRecorder is the mock recorder for MockEventCollector
type MockEventCollectorMockRecorder struct {
	mock *MockEventCollector
}

// NewMockEventCollector creates a new mock instance
func NewMockEventCollector(ctrl *gomock.Controller) *MockEventCollector {
	mock := &MockEventCollector{ctrl: ctrl}
	mock.recorder = &MockEventCollectorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockEventCollector) EXPECT() *MockEventCollectorMockRecorder {
	return m.recorder
}

// CollectFlowEvent mocks base method
func (m *MockEventCollector) CollectFlowEvent(record *collector.FlowRecord) {
	m.ctrl.Call(m, "CollectFlowEvent", record)
}

// CollectFlowEvent indicates an expected call of CollectFlowEvent
func (mr *MockEventCollectorMockRecorder) CollectFlowEvent(record interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CollectFlowEvent", reflect.TypeOf((*MockEventCollector)(nil).CollectFlowEvent), record)
}

// CollectContainerEvent mocks base method
func (m *MockEventCollector) CollectContainerEvent(record *collector.ContainerRecord) {
	m.ctrl.Call(m, "CollectContainerEvent", record)
}

// CollectContainerEvent indicates an expected call of CollectContainerEvent
func (mr *MockEventCollectorMockRecorder) CollectContainerEvent(record interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CollectContainerEvent", reflect.TypeOf((*MockEventCollector)(nil).CollectContainerEvent), record)
}
