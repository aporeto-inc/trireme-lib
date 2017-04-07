package rpcwrapper

// RPCClient is the client interface
type RPCClient interface {
	NewRPCClient(contextID string, channel string, rpcSecret string) error
	GetRPCClient(contextID string) (*RPCHdl, error)
	RemoteCall(contextID string, methodName string, req *Request, resp *Response) error
	DestroyRPCClient(contextID string)
	ContextList() []string
	CheckValidity(req *Request, secret string) bool
}

// RPCServer is the server interface
type RPCServer interface {
	StartServer(protocol string, path string, handler interface{}) error
	ProcessMessage(req *Request, secret string) bool
	CheckValidity(req *Request, secret string) bool
}
