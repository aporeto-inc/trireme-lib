// Code generated by MockGen. DO NOT EDIT.
// Source: controller/pkg/remoteenforcer/internal/statscollector/interfaces.go

// Package mockstatscollector is a generated GoMock package.
package mockstatscollector

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	collector "go.aporeto.io/trireme-lib/collector"
)

// MockCollectorReader is a mock of CollectorReader interface
// nolint
type MockCollectorReader struct {
	ctrl     *gomock.Controller
	recorder *MockCollectorReaderMockRecorder
}

// MockCollectorReaderMockRecorder is the mock recorder for MockCollectorReader
// nolint
type MockCollectorReaderMockRecorder struct {
	mock *MockCollectorReader
}

// NewMockCollectorReader creates a new mock instance
// nolint
func NewMockCollectorReader(ctrl *gomock.Controller) *MockCollectorReader {
	mock := &MockCollectorReader{ctrl: ctrl}
	mock.recorder = &MockCollectorReaderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
// nolint
func (m *MockCollectorReader) EXPECT() *MockCollectorReaderMockRecorder {
	return m.recorder
}

// Count mocks base method
// nolint
func (m *MockCollectorReader) Count() int {
	ret := m.ctrl.Call(m, "Count")
	ret0, _ := ret[0].(int)
	return ret0
}

// Count indicates an expected call of Count
// nolint
func (mr *MockCollectorReaderMockRecorder) Count() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Count", reflect.TypeOf((*MockCollectorReader)(nil).Count))
}

// GetAllRecords mocks base method
// nolint
func (m *MockCollectorReader) GetAllRecords() map[string]*collector.FlowRecord {
	ret := m.ctrl.Call(m, "GetAllRecords")
	ret0, _ := ret[0].(map[string]*collector.FlowRecord)
	return ret0
}

// GetAllRecords indicates an expected call of GetAllRecords
// nolint
func (mr *MockCollectorReaderMockRecorder) GetAllRecords() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllRecords", reflect.TypeOf((*MockCollectorReader)(nil).GetAllRecords))
}

// GetUserRecords mocks base method
// nolint
func (m *MockCollectorReader) GetUserRecords() map[string]*collector.UserRecord {
	ret := m.ctrl.Call(m, "GetUserRecords")
	ret0, _ := ret[0].(map[string]*collector.UserRecord)
	return ret0
}

// GetUserRecords indicates an expected call of GetUserRecords
// nolint
func (mr *MockCollectorReaderMockRecorder) GetUserRecords() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserRecords", reflect.TypeOf((*MockCollectorReader)(nil).GetUserRecords))
}

// FlushUserCache mocks base method
// nolint
func (m *MockCollectorReader) FlushUserCache() {
	m.ctrl.Call(m, "FlushUserCache")
}

// FlushUserCache indicates an expected call of FlushUserCache
// nolint
func (mr *MockCollectorReaderMockRecorder) FlushUserCache() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FlushUserCache", reflect.TypeOf((*MockCollectorReader)(nil).FlushUserCache))
}

// GetAllDataPathPacketRecords mocks base method
// nolint
func (m *MockCollectorReader) GetAllDataPathPacketRecords() []*collector.PacketReport {
	ret := m.ctrl.Call(m, "GetAllDataPathPacketRecords")
	ret0, _ := ret[0].([]*collector.PacketReport)
	return ret0
}

// GetAllDataPathPacketRecords indicates an expected call of GetAllDataPathPacketRecords
// nolint
func (mr *MockCollectorReaderMockRecorder) GetAllDataPathPacketRecords() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllDataPathPacketRecords", reflect.TypeOf((*MockCollectorReader)(nil).GetAllDataPathPacketRecords))
}

// GetAllCounterReports mocks base method
// nolint
func (m *MockCollectorReader) GetAllCounterReports() []*collector.CounterReport {
	ret := m.ctrl.Call(m, "GetAllCounterReports")
	ret0, _ := ret[0].([]*collector.CounterReport)
	return ret0
}

// GetAllCounterReports indicates an expected call of GetAllCounterReports
// nolint
func (mr *MockCollectorReaderMockRecorder) GetAllCounterReports() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllCounterReports", reflect.TypeOf((*MockCollectorReader)(nil).GetAllCounterReports))
}

// GetDNSReports mocks base method
// nolint
func (m *MockCollectorReader) GetDNSReports() chan *collector.DNSRequestReport {
	ret := m.ctrl.Call(m, "GetDNSReports")
	ret0, _ := ret[0].(chan *collector.DNSRequestReport)
	return ret0
}

// GetDNSReports indicates an expected call of GetDNSReports
// nolint
func (mr *MockCollectorReaderMockRecorder) GetDNSReports() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetDNSReports", reflect.TypeOf((*MockCollectorReader)(nil).GetDNSReports))
}

// GetPingReports mocks base method
// nolint
func (m *MockCollectorReader) GetPingReports() chan *collector.PingReport {
	ret := m.ctrl.Call(m, "GetPingReports")
	ret0, _ := ret[0].(chan *collector.PingReport)
	return ret0
}

// GetPingReports indicates an expected call of GetPingReports
// nolint
func (mr *MockCollectorReaderMockRecorder) GetPingReports() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPingReports", reflect.TypeOf((*MockCollectorReader)(nil).GetPingReports))
}

// MockCollector is a mock of Collector interface
// nolint
type MockCollector struct {
	ctrl     *gomock.Controller
	recorder *MockCollectorMockRecorder
}

// MockCollectorMockRecorder is the mock recorder for MockCollector
// nolint
type MockCollectorMockRecorder struct {
	mock *MockCollector
}

// NewMockCollector creates a new mock instance
// nolint
func NewMockCollector(ctrl *gomock.Controller) *MockCollector {
	mock := &MockCollector{ctrl: ctrl}
	mock.recorder = &MockCollectorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
// nolint
func (m *MockCollector) EXPECT() *MockCollectorMockRecorder {
	return m.recorder
}

// Count mocks base method
// nolint
func (m *MockCollector) Count() int {
	ret := m.ctrl.Call(m, "Count")
	ret0, _ := ret[0].(int)
	return ret0
}

// Count indicates an expected call of Count
// nolint
func (mr *MockCollectorMockRecorder) Count() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Count", reflect.TypeOf((*MockCollector)(nil).Count))
}

// GetAllRecords mocks base method
// nolint
func (m *MockCollector) GetAllRecords() map[string]*collector.FlowRecord {
	ret := m.ctrl.Call(m, "GetAllRecords")
	ret0, _ := ret[0].(map[string]*collector.FlowRecord)
	return ret0
}

// GetAllRecords indicates an expected call of GetAllRecords
// nolint
func (mr *MockCollectorMockRecorder) GetAllRecords() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllRecords", reflect.TypeOf((*MockCollector)(nil).GetAllRecords))
}

// GetUserRecords mocks base method
// nolint
func (m *MockCollector) GetUserRecords() map[string]*collector.UserRecord {
	ret := m.ctrl.Call(m, "GetUserRecords")
	ret0, _ := ret[0].(map[string]*collector.UserRecord)
	return ret0
}

// GetUserRecords indicates an expected call of GetUserRecords
// nolint
func (mr *MockCollectorMockRecorder) GetUserRecords() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserRecords", reflect.TypeOf((*MockCollector)(nil).GetUserRecords))
}

// FlushUserCache mocks base method
// nolint
func (m *MockCollector) FlushUserCache() {
	m.ctrl.Call(m, "FlushUserCache")
}

// FlushUserCache indicates an expected call of FlushUserCache
// nolint
func (mr *MockCollectorMockRecorder) FlushUserCache() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FlushUserCache", reflect.TypeOf((*MockCollector)(nil).FlushUserCache))
}

// GetAllDataPathPacketRecords mocks base method
// nolint
func (m *MockCollector) GetAllDataPathPacketRecords() []*collector.PacketReport {
	ret := m.ctrl.Call(m, "GetAllDataPathPacketRecords")
	ret0, _ := ret[0].([]*collector.PacketReport)
	return ret0
}

// GetAllDataPathPacketRecords indicates an expected call of GetAllDataPathPacketRecords
// nolint
func (mr *MockCollectorMockRecorder) GetAllDataPathPacketRecords() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllDataPathPacketRecords", reflect.TypeOf((*MockCollector)(nil).GetAllDataPathPacketRecords))
}

// GetAllCounterReports mocks base method
// nolint
func (m *MockCollector) GetAllCounterReports() []*collector.CounterReport {
	ret := m.ctrl.Call(m, "GetAllCounterReports")
	ret0, _ := ret[0].([]*collector.CounterReport)
	return ret0
}

// GetAllCounterReports indicates an expected call of GetAllCounterReports
// nolint
func (mr *MockCollectorMockRecorder) GetAllCounterReports() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllCounterReports", reflect.TypeOf((*MockCollector)(nil).GetAllCounterReports))
}

// GetDNSReports mocks base method
// nolint
func (m *MockCollector) GetDNSReports() chan *collector.DNSRequestReport {
	ret := m.ctrl.Call(m, "GetDNSReports")
	ret0, _ := ret[0].(chan *collector.DNSRequestReport)
	return ret0
}

// GetDNSReports indicates an expected call of GetDNSReports
// nolint
func (mr *MockCollectorMockRecorder) GetDNSReports() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetDNSReports", reflect.TypeOf((*MockCollector)(nil).GetDNSReports))
}

// GetPingReports mocks base method
// nolint
func (m *MockCollector) GetPingReports() chan *collector.PingReport {
	ret := m.ctrl.Call(m, "GetPingReports")
	ret0, _ := ret[0].(chan *collector.PingReport)
	return ret0
}

// GetPingReports indicates an expected call of GetPingReports
// nolint
func (mr *MockCollectorMockRecorder) GetPingReports() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPingReports", reflect.TypeOf((*MockCollector)(nil).GetPingReports))
}

// CollectFlowEvent mocks base method
// nolint
func (m *MockCollector) CollectFlowEvent(record *collector.FlowRecord) {
	m.ctrl.Call(m, "CollectFlowEvent", record)
}

// CollectFlowEvent indicates an expected call of CollectFlowEvent
// nolint
func (mr *MockCollectorMockRecorder) CollectFlowEvent(record interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CollectFlowEvent", reflect.TypeOf((*MockCollector)(nil).CollectFlowEvent), record)
}

// CollectContainerEvent mocks base method
// nolint
func (m *MockCollector) CollectContainerEvent(record *collector.ContainerRecord) {
	m.ctrl.Call(m, "CollectContainerEvent", record)
}

// CollectContainerEvent indicates an expected call of CollectContainerEvent
// nolint
func (mr *MockCollectorMockRecorder) CollectContainerEvent(record interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CollectContainerEvent", reflect.TypeOf((*MockCollector)(nil).CollectContainerEvent), record)
}

// CollectUserEvent mocks base method
// nolint
func (m *MockCollector) CollectUserEvent(record *collector.UserRecord) {
	m.ctrl.Call(m, "CollectUserEvent", record)
}

// CollectUserEvent indicates an expected call of CollectUserEvent
// nolint
func (mr *MockCollectorMockRecorder) CollectUserEvent(record interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CollectUserEvent", reflect.TypeOf((*MockCollector)(nil).CollectUserEvent), record)
}

// CollectTraceEvent mocks base method
// nolint
func (m *MockCollector) CollectTraceEvent(records []string) {
	m.ctrl.Call(m, "CollectTraceEvent", records)
}

// CollectTraceEvent indicates an expected call of CollectTraceEvent
// nolint
func (mr *MockCollectorMockRecorder) CollectTraceEvent(records interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CollectTraceEvent", reflect.TypeOf((*MockCollector)(nil).CollectTraceEvent), records)
}

// CollectPacketEvent mocks base method
// nolint
func (m *MockCollector) CollectPacketEvent(report *collector.PacketReport) {
	m.ctrl.Call(m, "CollectPacketEvent", report)
}

// CollectPacketEvent indicates an expected call of CollectPacketEvent
// nolint
func (mr *MockCollectorMockRecorder) CollectPacketEvent(report interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CollectPacketEvent", reflect.TypeOf((*MockCollector)(nil).CollectPacketEvent), report)
}

// CollectCounterEvent mocks base method
// nolint
func (m *MockCollector) CollectCounterEvent(counterReport *collector.CounterReport) {
	m.ctrl.Call(m, "CollectCounterEvent", counterReport)
}

// CollectCounterEvent indicates an expected call of CollectCounterEvent
// nolint
func (mr *MockCollectorMockRecorder) CollectCounterEvent(counterReport interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CollectCounterEvent", reflect.TypeOf((*MockCollector)(nil).CollectCounterEvent), counterReport)
}

// CollectDNSRequests mocks base method
// nolint
func (m *MockCollector) CollectDNSRequests(request *collector.DNSRequestReport) {
	m.ctrl.Call(m, "CollectDNSRequests", request)
}

// CollectDNSRequests indicates an expected call of CollectDNSRequests
// nolint
func (mr *MockCollectorMockRecorder) CollectDNSRequests(request interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CollectDNSRequests", reflect.TypeOf((*MockCollector)(nil).CollectDNSRequests), request)
}

// CollectPingEvent mocks base method
// nolint
func (m *MockCollector) CollectPingEvent(report *collector.PingReport) {
	m.ctrl.Call(m, "CollectPingEvent", report)
}

// CollectPingEvent indicates an expected call of CollectPingEvent
// nolint
func (mr *MockCollectorMockRecorder) CollectPingEvent(report interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CollectPingEvent", reflect.TypeOf((*MockCollector)(nil).CollectPingEvent), report)
}
