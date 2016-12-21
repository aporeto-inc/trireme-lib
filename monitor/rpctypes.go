package monitor

// EventInfo contains all the RPC info for a specific event
type EventInfo struct {
	EventType Event
	PUID      string
	Name      string
	Tags      map[string]string
	PID       string
	IPs       map[string]string
}

// RPCResponse encapsulate the error response if any
type RPCResponse struct {
	Error string
}
