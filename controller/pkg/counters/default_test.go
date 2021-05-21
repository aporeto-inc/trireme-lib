package counters

import (
	"errors"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func Test_DefaultCounterError(t *testing.T) {

	Convey("When I increment counter", t, func() {
		err := CounterError(ErrInvalidProtocol, errors.New("unknown protocol"))
		IncrementCounter(ErrInvalidProtocol)
		So(err, ShouldResemble, errors.New("unknown protocol"))
		So(defaultCounters.counters[ErrInvalidProtocol], ShouldEqual, 2)

		// Reset the global counters
		GetErrorCounters() // nolint
	})
}

func Test_DefaultGetErrorCounter(t *testing.T) {

	Convey("When I increment counter", t, func() {
		err := CounterError(ErrInvalidProtocol, errors.New("unknown protocol"))
		IncrementCounter(ErrInvalidProtocol)
		IncrementCounter(ErrInvalidProtocol)
		So(err, ShouldResemble, errors.New("unknown protocol"))
		So(defaultCounters.counters[ErrInvalidProtocol], ShouldEqual, 3)

		Convey("When I get the error counter", func() {
			c := GetErrorCounters()
			So(len(c), ShouldEqual, errMax)
			So(c[ErrInvalidProtocol], ShouldEqual, 3)
			So(defaultCounters.counters[ErrInvalidProtocol], ShouldEqual, 0)
		})
	})
}
