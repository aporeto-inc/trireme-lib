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
<<<<<<< HEAD
	ProcessMessageMock   func(req *Request) bool
=======
	ProcessMessageMock   func(req *Request, secret string) bool
>>>>>>> 9bc878e4b477ba6069afe7247dba88b8f2ba8f83
	ContextListMock      func() []string
}

// TestRPCClient
type TestRPCClient interface {
	RPCClient
	MockNewRPCClient(t *testing.T, impl func(contextID string, channel string, secret string) error)
	MockGetRPCClient(t *testing.T, impl func(contextID string) (*RPCHdl, error))
	MockRemoteCall(t *testing.T, impl func(contextID string, methodName string, req *Request, resp *Response) error)
	MockDestroyRPCClient(t *testing.T, impl func(contextID string))
	MockContextList(t *testing.T, impl func() []string)
}

// TestRPCServer
type TestRPCServer interface {
	RPCServer
	MockStartServer(t *testing.T, impl func(protocol string, path string, handler interface{}) error)
	MockProcessMessage(t *testing.T, impl func(req *Request, secret string) bool)
}

type testRPC struct {
	mocks       map[*testing.T]*mockedMethods
	lock        *sync.Mutex
	currentTest *testing.T
}

// NewTestRPCServer
func NewTestRPCServer() TestRPCServer {
	return &testRPC{
		lock:  &sync.Mutex{},
		mocks: map[*testing.T]*mockedMethods{},
	}
}

// NewTestRPCClient
func NewTestRPCClient() TestRPCClient {
	return &testRPC{
		lock:  &sync.Mutex{},
		mocks: map[*testing.T]*mockedMethods{},
	}
}
func (m *testRPC) MockNewRPCClient(t *testing.T, impl func(contextID string, channel string, secret string) error) {
	m.currentMocks(t).NewRPCClientMock = impl
}

func (m *testRPC) MockGetRPCClient(t *testing.T, impl func(contextID string) (*RPCHdl, error)) {
	m.currentMocks(t).GetRPCClientMock = impl
}

func (m *testRPC) MockRemoteCall(t *testing.T, impl func(contextID string, methodName string, req *Request, resp *Response) error) {
	m.currentMocks(t).RemoteCallMock = impl
}

func (m *testRPC) MockDestroyRPCClient(t *testing.T, impl func(contextID string)) {
	m.currentMocks(t).DestroyRPCClientMock = impl
}

func (m *testRPC) MockStartServer(t *testing.T, impl func(protocol string, path string, handler interface{}) error) {
	m.currentMocks(t).StartServerMock = impl

}

func (m *testRPC) MockProcessMessage(t *testing.T, impl func(req *Request, secret string) bool) {
	m.currentMocks(t).ProcessMessageMock = impl
}

func (m *testRPC) MockContextList(t *testing.T, impl func() []string) {
	m.currentMocks(t).ContextListMock = impl
}

<<<<<<< HEAD
func (m *testRPC) NewRPCClient(contextID string, channel string) error {
=======
func (m *testRPC) NewRPCClient(contextID string, channel string, secret string) error {
>>>>>>> 9bc878e4b477ba6069afe7247dba88b8f2ba8f83
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.NewRPCClientMock != nil {
		return mock.NewRPCClientMock(contextID, channel, secret)

	}
	return nil
}
func (m *testRPC) GetRPCClient(contextID string) (*RPCHdl, error) {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.GetRPCClientMock != nil {
		return mock.GetRPCClientMock(contextID)
	}
	return nil, nil
}
func (m *testRPC) RemoteCall(contextID string, methodName string, req *Request, resp *Response) error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.RemoteCallMock != nil {
		return mock.RemoteCallMock(contextID, methodName, req, resp)
	}
	return nil
}
func (m *testRPC) DestroyRPCClient(contextID string) {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.DestroyRPCClientMock != nil {
		mock.DestroyRPCClientMock(contextID)
		return
	}

}

func (m *testRPC) StartServer(protocol string, path string, handler interface{}) error {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.StartServerMock != nil {
		return mock.StartServerMock(protocol, path, handler)
	}
	return nil
}
func (m *testRPC) ProcessMessage(req *Request, secret string) bool {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.ProcessMessageMock != nil {
		return mock.ProcessMessageMock(req, secret)
	}
	return true
}

func (m *testRPC) ContextList() []string {
	if mock := m.currentMocks(m.currentTest); mock != nil && mock.ContextListMock != nil {
		return mock.ContextListMock()
	}
	return []string{}
}

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
