package pucontext

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func createPUContext() *PUContext {
	return &PUContext{
		id:           "contextID1",
		managementID: "12345678",
		counters:     make([]uint32, len(countedEvents)),
	}
}
func TestContextError(t *testing.T) {
	context := createPUContext()
	Convey("when an error is reported the corresponding counter is incremented", t, func() {
		Convey("I return each error on a valid pucontext and the counter is incremented and reset to zero once we read the error", func() {
			for _, err := range countedEvents {

				returnederr := context.PuContextError(err.index, "")
				val, ok := returnederr.(PuErrors)
				So(ok, ShouldBeTrue)
				So(val.index, ShouldEqual, err.index)
				errCounters := context.GetErrorCounters()
				So(errCounters[err.index].Value, ShouldEqual, 1)
				So(context.counters[err.index], ShouldEqual, 0)
				getError := GetError(returnederr)
				So(getError, ShouldEqual, err.index)
			}
		})
		Convey("I return each error on with a n unknow pu  and the counter is incremented and reset to zero once we read the error", func() {
			for _, err := range countedEvents {

				returnederr := PuContextError(err.index, "")
				val, ok := returnederr.(PuErrors)
				So(ok, ShouldBeTrue)
				So(val.index, ShouldEqual, err.index)
				errCounters := unknownPU.GetErrorCounters()
				So(errCounters[err.index].Value, ShouldEqual, 1)
				So(unknownPU.counters[err.index], ShouldEqual, 0)
				getError := GetError(returnederr)
				So(getError, ShouldEqual, err.index)
			}
		})
	})
}
