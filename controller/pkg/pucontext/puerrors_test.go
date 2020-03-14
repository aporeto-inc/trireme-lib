// +build !windows

package pucontext

import (
	"fmt"
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

func TestGetErrorCounters(t *testing.T) {
	Convey("When i report an error on unknown PU and call getErrorCounter", t, func() {
		err := PuContextError(ErrNetSynNotSeen, "net Syn not seen")
		So(err, ShouldNotBeNil)
		Convey("I call get Error counters", func() {
			report := GetErrorCounters()
			So(report[ErrNetSynNotSeen].Value, ShouldEqual, 1)
			report = GetErrorCounters()
			So(report[ErrNetSynNotSeen].Value, ShouldEqual, 0)
		})
	})
}

func TestGetError(t *testing.T) {
	Convey("When i pass an error of we return the right errtype", t, func() {
		for index, event := range countedEvents {
			errType := GetError(event)
			fmt.Println(event.err)
			So(int(errType), ShouldEqual, index)
		}
	})
}
