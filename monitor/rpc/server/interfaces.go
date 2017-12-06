package rpcserver

// RPCServer is an interface implemnted by the RPC server.
type RPCServer interface {
	Register(rcvr interface{}) error
	Start() error
	Stop()
}
