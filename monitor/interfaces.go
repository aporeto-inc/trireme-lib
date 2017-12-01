package monitor

// A Monitor is an interface implmented to start/stop monitors.
type Monitor interface {

	// Start starts the monitor.
	Start() error

	// Stop Stops the monitor.
	Stop() error
}
