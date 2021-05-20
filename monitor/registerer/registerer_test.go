package registerer

import (
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/processor/mockprocessor"
)

func TestNew(t *testing.T) {
	Convey("When I create a new registrer", t, func() {
		r := New()
		Convey("It should be valid", func() {
			So(r, ShouldNotBeNil)
			So(r.(*registerer).handlers, ShouldNotBeNil)
		})
	})
}

func TestRegisterProcessor(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I register a new processor", t, func() {
		r := New()

		processor := mockprocessor.NewMockProcessor(ctrl)
		err := r.RegisterProcessor(common.ContainerPU, processor)

		Convey("The registration should be succesfull", func() {
			So(err, ShouldBeNil)
			h, ok := r.(*registerer).handlers[common.ContainerPU]
			So(ok, ShouldBeTrue)
			So(h, ShouldNotBeNil)
			So(len(h), ShouldEqual, 6)
		})

		Convey("If I ask for the handler, I should ge the right handler", func() {
			_, err := r.GetHandler(common.ContainerPU, common.EventCreate)
			So(err, ShouldBeNil)

			_, err = r.GetHandler(common.ContainerPU, common.EventStart)
			So(err, ShouldBeNil)

			_, err = r.GetHandler(common.ContainerPU, common.EventDestroy)
			So(err, ShouldBeNil)

			_, err = r.GetHandler(common.ContainerPU, common.EventPause)
			So(err, ShouldBeNil)
		})

		Convey("If I ask for the handler with a bad PUType, I should get an error ", func() {
			_, err := r.GetHandler(common.LinuxProcessPU, common.EventCreate)
			So(err, ShouldNotBeNil)
		})

		Convey("If I ask for the handler, with a bad event, I should get an error ", func() {
			_, err := r.GetHandler(common.LinuxProcessPU, common.Event("300"))
			So(err, ShouldNotBeNil)
		})

		Convey("If I try to register the processor twice, I should get an error ", func() {
			err := r.RegisterProcessor(common.ContainerPU, processor)
			So(err, ShouldNotBeNil)
		})
	})

}
