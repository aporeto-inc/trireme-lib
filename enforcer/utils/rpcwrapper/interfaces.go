package rpcwrapper

// RPCClient is the client interface
type RPCClient interface {
	NewRPCClient(contextID string, channel string) error
	GetRPCClient(contextID string) (*RPCHdl, error)
	RemoteCall(contextID string, methodName string, req *Request, resp *Response) error
	DestroyRPCClient(contextID string)
	ContextList() []string
}

// RPCServer is the server interface
type RPCServer interface {
	StartServer(protocol string, path string, handler interface{}) error
	ProcessMessage(req *Request) bool
}
