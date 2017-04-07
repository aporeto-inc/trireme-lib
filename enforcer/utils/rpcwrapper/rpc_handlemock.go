package rpcwrapper

import (
	"net/rpc"
	"sync"
	"testing"
)

// MockRPCHdl is mock of rpchdl
type MockRPCHdl struct {
	Client  *rpc.Client
	Channel string
}

type mockedMethods struct {
	NewRPCClientMock     func(contextID string, channel string, secret string) error
	GetRPCClientMock     func(contextID string) (*RPCHdl, error)
	RemoteCallMock       func(contextID string, methodName string, req *Request, resp *Response) error
	DestroyRPCClientMock func(contextID string)
	StartServerMock      func(protocol string, path string, handler interface{}) error
	ProcessMessageMock   func(req *Request, secret string) bool
	ContextListMock      func() []string
	CheckValidityMock    func(req *Request, secret string) bool
}

// TestRPCClient is a RPC Client used for test
type TestRPCClient interface {
	RPCClient
	MockNewRPCClient(t *testing.T, impl func(contextID string, channel string, secret string) error)
	MockGetRPCClient(t *testing.T, impl func(contextID string) (*RPCHdl, error))
	MockRemoteCall(t *testing.T, impl func(contextID string, methodName string, req *Request, resp *Response) error)
	MockDestroyRPCClient(t *testing.T, impl func(contextID string))
	MockContextList(t *testing.T, impl func() []string)
	MockCheckValidity(t *testing.T, impl func(req *Request, secret string) bool)
}

// TestRPCServer is a RPC Server used for test
type TestRPCServer interface {
	RPCServer
	MockStartServer(t *testing.T, impl func(protocol string, path string, handler interface{}) error)
	MockProcessMessage(t *testing.T, impl func(req *Request, secret string) bool)
	MockCheckValidity(t *testing.T, impl func(req *Request, secret string) bool)
}

type testRPC struct {
	mocks       map[*testing.T]*mockedMethods
	lock        *sync.Mutex
	currentTest *testing.T
}

// NewTestRPCServer is a Test RPC Server
func NewTestRPCServer() TestRPCServer {
	return &testRPC{
		lock:  &sync.Mutex{},
		mocks: map[*testing.T]*mockedMethods{},
	}
}

// NewTestRPCClient is a Test RPC Client
func NewTestRPCClient() TestRPCClient {
	return &testRPC{
		lock:  &sync.Mutex{},
		mocks: map[*testing.T]*mockedMethods{},
	}
}

// MockNewRPCClient mocks the NewRPCClient function
func (m *testRPC) MockNewRPCClient(t *testing.T, impl func(contextID string, channel string, secret string) error) {
	m.currentMocks(t).NewRPCClientMock = impl
}

// MockGetRPCClient mocks the GetRPCClient function
func (m *testRPC) MockGetRPCClient(t *testing.T, impl func(contextID string) (*RPCHdl, error)) {
	m.currentMocks(t).GetRPCClientMock = impl
}

// MockRemoteCall mocks the RemoteCall function
func (m *testRPC) MockRemoteCall(t *testing.T, impl func(contextID string, methodName string, req *Request, resp *Response) error) {
	m.currentMocks(t).RemoteCallMock = impl
}

// MockDestroyRPCClient mocks the DestroyRPCClient function
func (m *testRPC) MockDestroyRPCClient(t *testing.T, impl func(contextID string)) {
	m.currentMocks(t).DestroyRPCClientMock = impl
}

// MockStartServer mocks the StartServer function
func (m *testRPC) MockStartServer(t *testing.T, impl func(protocol string, path string, handler interface{}) error) {
	m.currentMocks(t).StartServerMock = impl

}

// MockProcessMessage mocks the ProcessMessage function
func (m *testRPC) MockProcessMessage(t *testing.T, impl func(req *Request, secret string) bool) {
	m.currentMocks(t).ProcessMessageMock = impl
}

// MockContextList mocks the ContextList function
func (m *testRPC) MockContextList(t *testing.T, impl func() []string) {
	m.currentMocks(t).ContextListMock = impl
}

// MockCheckValidity mocks the CheckValidity function
func (m *testRPC) MockCheckValidity(t *testing.T, impl func(req *Request, secret string) bool) {
	m.currentMocks(t).CheckValidityMock = impl
}

// NewRPCClient implements the new interface
func (m *testRPC) NewRPCClient(contextID string, channel string, secret string) error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.NewRPCClientMock != nil {
		return mock.NewRPCClientMock(contextID, channel, secret)
	}
	return nil
}

// GetRPCClient implements the interface with a mock
func (m *testRPC) GetRPCClient(contextID string) (*RPCHdl, error) {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.GetRPCClientMock != nil {
		return mock.GetRPCClientMock(contextID)
	}
	return nil, nil
}

// RemoteCall implements the interface with a mock
func (m *testRPC) RemoteCall(contextID string, methodName string, req *Request, resp *Response) error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.RemoteCallMock != nil {
		return mock.RemoteCallMock(contextID, methodName, req, resp)
	}
	return nil
}

// DestroyRPCClient implements the interface with a Mock
func (m *testRPC) DestroyRPCClient(contextID string) {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.DestroyRPCClientMock != nil {
		mock.DestroyRPCClientMock(contextID)
		return
	}
}

// CheckValidity implements the interface with a mock
func (m *testRPC) CheckValidity(req *Request, secret string) bool {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.DestroyRPCClientMock != nil {
		return mock.CheckValidityMock(req, secret)
	}
	return false
}

// StartServer implements the interface with a mock
func (m *testRPC) StartServer(protocol string, path string, handler interface{}) error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.StartServerMock != nil {
		return mock.StartServerMock(protocol, path, handler)
	}
	return nil
}

// ProcessMessage implements the interface with a mock
func (m *testRPC) ProcessMessage(req *Request, secret string) bool {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.ProcessMessageMock != nil {
		return mock.ProcessMessageMock(req, secret)
	}
	return true
}

// ContextList implements the interface with a mock
func (m *testRPC) ContextList() []string {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.ContextListMock != nil {
		return mock.ContextListMock()
	}
	return []string{}
}

// currentMocks returns the list of current mocks
func (m *testRPC) currentMocks(t *testing.T) *mockedMethods {
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
