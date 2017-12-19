package rpcmonitor

// Listener is an interface to allow us to listen to eventinfo.EventInfo over RPC channels
type Listener interface {
	Start() error
	Stop() error
}
