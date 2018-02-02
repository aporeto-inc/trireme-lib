package rpcmonitor

import "context"

// Listener is an interface to allow us to listen to eventinfo.EventInfo over RPC channels
type Listener interface {
	Run(ctx context.Context) error
}
