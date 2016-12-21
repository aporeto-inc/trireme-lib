package monitor

// EventInfo contains all the RPC info for a specific event
type EventInfo struct {
	EventType Event
	EventName string
	PID       string
}

// RPCResponse encapsulate the error response if any
type RPCResponse struct {
	Error string
}
