package counters

import (
	"sync/atomic"

	"go.aporeto.io/trireme-lib/collector"
)

// Bad PU to hold counters for packets we know nothing about. We cant figure out context
var defaultCounters = NewCounters()

// CounterError is a convinence function which returns error as well as increments the counter.
func CounterError(t CounterTypes, err error) error { // nolint

	atomic.AddUint32(&defaultCounters.counters[int(t)], 1)

	return err
}

// IncrementCounter increments counters for a given PU
func IncrementCounter(err CounterTypes) {
	atomic.AddUint32(&defaultCounters.counters[int(err)], 1)
}

// GetErrorCounters returns the error counters and resets the counters to zero
func GetErrorCounters() []collector.Counters {

	defaultCounters.Lock()
	defer defaultCounters.Unlock()

	report := make([]collector.Counters, totalCounters)

	for index := range defaultCounters.counters {
		report[index] = collector.Counters{
			Value: atomic.SwapUint32(&defaultCounters.counters[index], 0),
		}
	}

	return report
}
