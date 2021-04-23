package counters

import (
	"sync/atomic"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
)

// NewCounters initializes new counters handler. Thread safe.
func NewCounters() *Counters {
	return &Counters{}
}

// CounterNames returns an array of names
func CounterNames() []string {
	names := make([]string, errMax+1)
	var ct CounterType
	for ct = 0; ct <= errMax; ct++ {
		names[ct] = ct.String()
	}
	return names[:errMax]
}

// CounterError is a convinence function which returns error as well as increments the counter.
func (c *Counters) CounterError(t CounterType, err error) error {
	c.IncrementCounter(t)
	return err
}

// IncrementCounter increments counters for a given PU
func (c *Counters) IncrementCounter(t CounterType) {
	atomic.AddUint32(&c.counters[int(t)], 1)
}

// GetErrorCounters returns the error counters and resets the counters to zero
func (c *Counters) GetErrorCounters() []collector.Counters {

	c.Lock()

	report := make([]collector.Counters, errMax+1)
	for index := range c.counters {
		report[index] = collector.Counters(atomic.SwapUint32(&c.counters[index], 0))
	}

	c.Unlock()
	return report[:errMax]
}
