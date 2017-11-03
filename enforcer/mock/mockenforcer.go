// nolint
// Automatically generated by MockGen. DO NOT EDIT!
// Source: interfaces.go

package mock_enforcer

import (
	enforcer "github.com/aporeto-inc/trireme/enforcer"
	pucontext "github.com/aporeto-inc/trireme/enforcer/pucontext"
	fqconfig "github.com/aporeto-inc/trireme/enforcer/utils/fqconfig"
	packet "github.com/aporeto-inc/trireme/enforcer/utils/packet"
	secrets "github.com/aporeto-inc/trireme/enforcer/utils/secrets"
	tokens "github.com/aporeto-inc/trireme/enforcer/utils/tokens"
	policy "github.com/aporeto-inc/trireme/policy"
	gomock "github.com/golang/mock/gomock"
)

// Mock of PolicyEnforcer interface
type MockPolicyEnforcer struct {
	ctrl     *gomock.Controller
	recorder *_MockPolicyEnforcerRecorder
}

// Recorder for MockPolicyEnforcer (not exported)
type _MockPolicyEnforcerRecorder struct {
	mock *MockPolicyEnforcer
}

func NewMockPolicyEnforcer(ctrl *gomock.Controller) *MockPolicyEnforcer {
	mock := &MockPolicyEnforcer{ctrl: ctrl}
	mock.recorder = &_MockPolicyEnforcerRecorder{mock}
	return mock
}

func (_m *MockPolicyEnforcer) EXPECT() *_MockPolicyEnforcerRecorder {
	return _m.recorder
}

func (_m *MockPolicyEnforcer) Enforce(contextID string, puInfo *policy.PUInfo) error {
	ret := _m.ctrl.Call(_m, "Enforce", contextID, puInfo)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockPolicyEnforcerRecorder) Enforce(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Enforce", arg0, arg1)
}

func (_m *MockPolicyEnforcer) Unenforce(contextID string) error {
	ret := _m.ctrl.Call(_m, "Unenforce", contextID)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockPolicyEnforcerRecorder) Unenforce(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Unenforce", arg0)
}

func (_m *MockPolicyEnforcer) GetFilterQueue() *fqconfig.FilterQueue {
	ret := _m.ctrl.Call(_m, "GetFilterQueue")
	ret0, _ := ret[0].(*fqconfig.FilterQueue)
	return ret0
}

func (_mr *_MockPolicyEnforcerRecorder) GetFilterQueue() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetFilterQueue")
}

func (_m *MockPolicyEnforcer) Start() error {
	ret := _m.ctrl.Call(_m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockPolicyEnforcerRecorder) Start() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Start")
}

func (_m *MockPolicyEnforcer) Stop() error {
	ret := _m.ctrl.Call(_m, "Stop")
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockPolicyEnforcerRecorder) Stop() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Stop")
}

// Mock of PublicKeyAdder interface
type MockPublicKeyAdder struct {
	ctrl     *gomock.Controller
	recorder *_MockPublicKeyAdderRecorder
}

// Recorder for MockPublicKeyAdder (not exported)
type _MockPublicKeyAdderRecorder struct {
	mock *MockPublicKeyAdder
}

func NewMockPublicKeyAdder(ctrl *gomock.Controller) *MockPublicKeyAdder {
	mock := &MockPublicKeyAdder{ctrl: ctrl}
	mock.recorder = &_MockPublicKeyAdderRecorder{mock}
	return mock
}

func (_m *MockPublicKeyAdder) EXPECT() *_MockPublicKeyAdderRecorder {
	return _m.recorder
}

func (_m *MockPublicKeyAdder) PublicKeyAdd(host string, cert []byte) error {
	ret := _m.ctrl.Call(_m, "PublicKeyAdd", host, cert)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockPublicKeyAdderRecorder) PublicKeyAdd(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "PublicKeyAdd", arg0, arg1)
}

// Mock of PacketProcessor interface
type MockPacketProcessor struct {
	ctrl     *gomock.Controller
	recorder *_MockPacketProcessorRecorder
}

// Recorder for MockPacketProcessor (not exported)
type _MockPacketProcessorRecorder struct {
	mock *MockPacketProcessor
}

func NewMockPacketProcessor(ctrl *gomock.Controller) *MockPacketProcessor {
	mock := &MockPacketProcessor{ctrl: ctrl}
	mock.recorder = &_MockPacketProcessorRecorder{mock}
	return mock
}

func (_m *MockPacketProcessor) EXPECT() *_MockPacketProcessorRecorder {
	return _m.recorder
}

func (_m *MockPacketProcessor) Initialize(s secrets.Secrets, fq *fqconfig.FilterQueue) {
	_m.ctrl.Call(_m, "Initialize", s, fq)
}

func (_mr *_MockPacketProcessorRecorder) Initialize(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Initialize", arg0, arg1)
}

func (_m *MockPacketProcessor) PreProcessTCPAppPacket(p *packet.Packet, context *pucontext.PU, conn *enforcer.TCPConnection) bool {
	ret := _m.ctrl.Call(_m, "PreProcessTCPAppPacket", p, context, conn)
	ret0, _ := ret[0].(bool)
	return ret0
}

func (_mr *_MockPacketProcessorRecorder) PreProcessTCPAppPacket(arg0, arg1, arg2 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "PreProcessTCPAppPacket", arg0, arg1, arg2)
}

func (_m *MockPacketProcessor) PostProcessTCPAppPacket(p *packet.Packet, action interface{}, context *pucontext.PU, conn *enforcer.TCPConnection) bool {
	ret := _m.ctrl.Call(_m, "PostProcessTCPAppPacket", p, action, context, conn)
	ret0, _ := ret[0].(bool)
	return ret0
}

func (_mr *_MockPacketProcessorRecorder) PostProcessTCPAppPacket(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "PostProcessTCPAppPacket", arg0, arg1, arg2, arg3)
}

func (_m *MockPacketProcessor) PreProcessTCPNetPacket(p *packet.Packet, context *pucontext.PU, conn *enforcer.TCPConnection) bool {
	ret := _m.ctrl.Call(_m, "PreProcessTCPNetPacket", p, context, conn)
	ret0, _ := ret[0].(bool)
	return ret0
}

func (_mr *_MockPacketProcessorRecorder) PreProcessTCPNetPacket(arg0, arg1, arg2 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "PreProcessTCPNetPacket", arg0, arg1, arg2)
}

func (_m *MockPacketProcessor) PostProcessTCPNetPacket(p *packet.Packet, action interface{}, claims *tokens.ConnectionClaims, context *pucontext.PU, conn *enforcer.TCPConnection) bool {
	ret := _m.ctrl.Call(_m, "PostProcessTCPNetPacket", p, action, claims, context, conn)
	ret0, _ := ret[0].(bool)
	return ret0
}

func (_mr *_MockPacketProcessorRecorder) PostProcessTCPNetPacket(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "PostProcessTCPNetPacket", arg0, arg1, arg2, arg3, arg4)
}
