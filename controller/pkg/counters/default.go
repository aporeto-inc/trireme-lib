package counters

import (
	"go.aporeto.io/enforcerd/trireme-lib/collector"
)

// defaultCounters are a global instance of counters.
// These are used when we dont have a PU context.
var defaultCounters = NewCounters()

// CounterError is a convinence function which returns error as well as increments the counter.
func CounterError(t CounterType, err error) error { // nolint
	return defaultCounters.CounterError(t, err)
}

// IncrementCounter increments counters for a given PU
func IncrementCounter(err CounterType) {
	defaultCounters.IncrementCounter(err)
}

// GetErrorCounters returns the error counters and resets the counters to zero
func GetErrorCounters() []collector.Counters {
	return defaultCounters.GetErrorCounters()
}
