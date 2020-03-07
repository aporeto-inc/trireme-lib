package counters

import (
	"errors"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func Test_NewCounters(t *testing.T) {

	Convey("When I create new error counters", t, func() {
		ec := NewCounters()
		So(ec, ShouldNotBeNil)
		So(len(ec.counters), ShouldEqual, totalCounters)
	})
}

func Test_CounterError(t *testing.T) {

	Convey("When I create new error counters", t, func() {
		ec := NewCounters()
		So(ec, ShouldNotBeNil)
		So(len(ec.counters), ShouldEqual, totalCounters)

		Convey("When I increment counter", func() {
			err := ec.CounterError(ErrInvalidProtocol, errors.New("unknown protocol"))
			ec.IncrementCounter(ErrInvalidProtocol)
			So(err, ShouldResemble, errors.New("unknown protocol"))
			So(ec.counters[ErrInvalidProtocol], ShouldEqual, 2)
		})
	})
}

func Test_GetErrorCounter(t *testing.T) {

	Convey("When I create new error counters", t, func() {
		ec := NewCounters()
		So(ec, ShouldNotBeNil)
		So(len(ec.counters), ShouldEqual, totalCounters)

		Convey("When I increment counter and get error", func() {
			err := ec.CounterError(ErrInvalidProtocol, errors.New("unknown protocol"))
			ec.IncrementCounter(ErrInvalidProtocol)
			ec.IncrementCounter(ErrInvalidProtocol)

			So(err, ShouldResemble, errors.New("unknown protocol"))
			So(ec.counters[ErrInvalidProtocol], ShouldEqual, 3)

			c := ec.GetErrorCounters()

			So(len(c), ShouldEqual, totalCounters)
			So(c[ErrInvalidProtocol], ShouldEqual, 3)
			So(ec.counters[ErrInvalidProtocol], ShouldEqual, 0)
		})
	})
}
