package linuxmonitor

import (
	"errors"
	"io/ioutil"
	"os"
	"testing"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/internal/contextstore/mock"
	"github.com/aporeto-inc/trireme-lib/mock"
	"github.com/aporeto-inc/trireme-lib/monitor"
	"github.com/aporeto-inc/trireme-lib/monitor/linuxmonitor/cgnetcls/mock"
	"github.com/aporeto-inc/trireme-lib/monitor/rpcmonitor"
	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
)

func testLinuxProcessor() *LinuxProcessor {
	return NewCustomLinuxProcessor("/tmp", &collector.DefaultCollector{}, nil, rpcmonitor.DefaultRPCMetadataExtractor, "./")

}

func TestCreate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a valid processor", t, func() {
		puHandler := mock_trireme.NewMockProcessingUnitsHandler(ctrl)
		store := mockcontextstore.NewMockContextStore(ctrl)

		p := testLinuxProcessor()
		p.puHandler = puHandler
		p.contextStore = store

		Convey("When I try a create event with invalid PU ID, ", func() {
			event := &rpcmonitor.EventInfo{
				PUID: "/@#$@",
			}
			Convey("I should get an error", func() {
				err := p.Create(event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get a create event that is valid", func() {
			event := &rpcmonitor.EventInfo{
				PUID: "1234",
			}
			puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any()).Return(nil)
			Convey("I should get no error,", func() {
				err := p.Create(event)
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestStop(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a valid processor", t, func() {
		puHandler := mock_trireme.NewMockProcessingUnitsHandler(ctrl)
		store := mockcontextstore.NewMockContextStore(ctrl)

		p := testLinuxProcessor()
		p.puHandler = puHandler
		p.contextStore = store
		p.netcls = mock_cgnetcls.NewMockCgroupnetcls(ctrl)

		Convey("When I get a stop event that is valid", func() {
			event := &rpcmonitor.EventInfo{
				PUID: "/trireme/1234",
			}

			puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any()).Return(nil)
			Convey("I should get the status of the upstream function", func() {
				err := p.Stop(event)
				So(err, ShouldBeNil)
			})
		})

	})
}

// TODO: remove nolint
// nolint
func TestDestroy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	dummyPUPath := "/var/run/trireme/linux/1234"
	ioutil.WriteFile(dummyPUPath, []byte{}, 0644) //nolint

	defer os.RemoveAll(dummyPUPath) //nolint
	Convey("Given a valid processor", t, func() {
		puHandler := mock_trireme.NewMockProcessingUnitsHandler(ctrl)
		store := mockcontextstore.NewMockContextStore(ctrl)

		p := testLinuxProcessor()
		p.puHandler = puHandler
		p.contextStore = store
		mockcls := mock_cgnetcls.NewMockCgroupnetcls(ctrl)
		p.netcls = mockcls

		Convey("When I get a destroy event that is valid", func() {
			event := &rpcmonitor.EventInfo{
				PUID: "/trireme/1234",
			}
			mockcls.EXPECT().DeleteCgroup(gomock.Any()).Return(nil)
			store.EXPECT().Remove(gomock.Any()).Return(nil)

			puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any()).Return(nil)
			Convey("I should get the status of the upstream function", func() {
				err := p.Destroy(event)
				So(err, ShouldBeNil)
			})
		})

	})
}

func TestPause(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a valid processor", t, func() {
		puHandler := mock_trireme.NewMockProcessingUnitsHandler(ctrl)
		store := mockcontextstore.NewMockContextStore(ctrl)

		p := testLinuxProcessor()
		p.puHandler = puHandler
		p.contextStore = store

		Convey("When I get a pause event that is valid", func() {
			event := &rpcmonitor.EventInfo{
				PUID: "/trireme/1234",
			}

			puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any()).Return(nil)
			Convey("I should get the status of the upstream function", func() {
				err := p.Pause(event)
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestStart(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a valid processor", t, func() {
		puHandler := mock_trireme.NewMockProcessingUnitsHandler(ctrl)
		store := mockcontextstore.NewMockContextStore(ctrl)

		p := testLinuxProcessor()
		p.puHandler = puHandler
		p.contextStore = store

		Convey("When I get a start event with no PUID", func() {
			event := &rpcmonitor.EventInfo{
				PUID: "",
			}
			Convey("I should get an error", func() {
				err := p.Start(event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get a start event that is valid that fails on the metadata extractor", func() {
			event := &rpcmonitor.EventInfo{
				Name: "PU",
			}
			Convey("I should get an error", func() {
				err := p.Start(event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get a start event and setting the PU runtime fails", func() {
			event := &rpcmonitor.EventInfo{
				Name:      "PU",
				PID:       "1",
				PUID:      "12345",
				EventType: monitor.EventStop,
				PUType:    constants.LinuxProcessPU,
			}
			Convey("I should get an error ", func() {
				puHandler.EXPECT().SetPURuntime(gomock.Any(), gomock.Any()).Return(errors.New("error"))
				err := p.Start(event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get a start event and the upstream returns an error ", func() {
			event := &rpcmonitor.EventInfo{
				Name:      "PU",
				PID:       "1",
				PUID:      "12345",
				EventType: monitor.EventStop,
				PUType:    constants.LinuxProcessPU,
			}
			Convey("I should get an error ", func() {
				puHandler.EXPECT().SetPURuntime(gomock.Any(), gomock.Any()).Return(nil)

				puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any()).Return(errors.New("error"))
				err := p.Start(event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get a start event and create group fails ", func() {
			event := &rpcmonitor.EventInfo{
				Name:      "PU",
				PID:       "1",
				PUID:      "12345",
				EventType: monitor.EventStop,
				PUType:    constants.LinuxProcessPU,
			}

			mockcls := mock_cgnetcls.NewMockCgroupnetcls(ctrl)
			p.netcls = mockcls

			Convey("I should get an error ", func() {
				puHandler.EXPECT().SetPURuntime(gomock.Any(), gomock.Any()).Return(nil)
				puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any()).Return(nil)

				mockcls.EXPECT().Creategroup(gomock.Any()).Return(errors.New("error"))
				err := p.Start(event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get a start event and the runtime options don't have a mark value", func() {
			event := &rpcmonitor.EventInfo{
				Name:      "PU",
				PID:       "1",
				PUID:      "12345",
				EventType: monitor.EventStop,
				PUType:    constants.LinuxProcessPU,
			}

			mockcls := mock_cgnetcls.NewMockCgroupnetcls(ctrl)
			p.netcls = mockcls

			Convey("I should get an error ", func() {
				puHandler.EXPECT().SetPURuntime(gomock.Any(), gomock.Any()).Return(nil)
				puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any()).Return(nil)

				mockcls.EXPECT().Creategroup(gomock.Any()).Return(nil)
				mockcls.EXPECT().DeleteCgroup(gomock.Any()).Return(nil)
				err := p.Start(event)
				So(err, ShouldNotBeNil)
			})
		})

	})
}

func TestResync(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a valid processor", t, func() {
		puHandler := mock_trireme.NewMockProcessingUnitsHandler(ctrl)
		store := mockcontextstore.NewMockContextStore(ctrl)
		cls := mock_cgnetcls.NewMockCgroupnetcls(ctrl)

		p := testLinuxProcessor()
		p.puHandler = puHandler
		p.contextStore = store
		p.netcls = cls

		Convey("When we cannot open the context store it returns an error", func() {
			store.EXPECT().Walk().Return(nil, errors.New("no store"))

			Convey("Start server returns no error", func() {
				err := p.ReSync(nil)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When the context is invalid it should return no error - just ignore", func() {
			contextlist := make(chan string, 2)
			contextlist <- "test1"
			contextlist <- ""

			store.EXPECT().Walk().Return(contextlist, nil)
			store.EXPECT().Retrieve("/test1", gomock.Any()).Return(errors.New("invalid context"))

			Convey("Start server returns no error", func() {
				err := p.ReSync(nil)
				So(err, ShouldBeNil)
			})
		})

		Convey("When we discover invalid json and we can't remove the bad context", func() {
			contextlist := make(chan string, 2)
			contextlist <- "test1"
			contextlist <- ""

			eventInfo := rpcmonitor.EventInfo{
				PUType:    constants.LinuxProcessPU,
				EventType: monitor.EventStart,
				PUID:      "/test1",
			}

			store.EXPECT().Walk().Return(contextlist, nil)
			store.EXPECT().Retrieve("/test1", gomock.Any()).SetArg(1, eventInfo).Return(nil)
			store.EXPECT().Remove("/test1").Return(nil)

			Convey("Start server returns no error", func() {
				err := p.ReSync(nil)
				So(err, ShouldBeNil)
			})
		})
	})
}
