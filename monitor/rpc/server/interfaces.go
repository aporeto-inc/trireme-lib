package rpcserver

import "context"

// RPCServer is an interface implemnted by the RPC server.
type RPCServer interface {
	Register(rcvr interface{}) error
	Run(ctx context.Context) error
}
