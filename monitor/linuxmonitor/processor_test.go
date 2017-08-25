package linuxmonitor

import (
	"fmt"
	"testing"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/mock"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/contextstore"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls/mock"
	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"
	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
)

func testLinuxProcessor(collector collector.EventCollector, puHandler monitor.ProcessingUnitsHandler, metadataExtractor rpcmonitor.RPCMetadataExtractor, releasePath string) *LinuxProcessor {
	return &LinuxProcessor{
		collector:         collector,
		puHandler:         puHandler,
		metadataExtractor: metadataExtractor,
		netcls:            cgnetcls.NewCgroupNetController(releasePath),
		contextStore:      contextstore.NewCustomContextStore("/tmp"),
	}
}

func TestCreate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a valid processor", t, func() {
		puHandler := mock_trireme.NewMockProcessingUnitsHandler(ctrl)
		p := testLinuxProcessor(&collector.DefaultCollector{}, puHandler, rpcmonitor.DefaultRPCMetadataExtractor, "")

		Convey("When I get an event with no PUID", func() {
			event := &rpcmonitor.EventInfo{
				PUID: "",
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
		p := testLinuxProcessor(&collector.DefaultCollector{}, puHandler, rpcmonitor.DefaultRPCMetadataExtractor, "")
		p.netcls = mock_cgnetcls.NewMockCgroupnetcls(ctrl)

		Convey("When I get a stop event with no PUID", func() {
			event := &rpcmonitor.EventInfo{
				PUID: "",
			}
			Convey("I should get an error", func() {
				err := p.Stop(event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get stop event without the Trireme Prefix", func() {
			event := &rpcmonitor.EventInfo{
				PUID: "/blah/blah",
			}
			Convey("It should be ignored", func() {
				err := p.Stop(event)
				So(err, ShouldBeNil)
			})
		})

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

func TestDestroy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a valid processor", t, func() {
		puHandler := mock_trireme.NewMockProcessingUnitsHandler(ctrl)
		p := testLinuxProcessor(&collector.DefaultCollector{}, puHandler, rpcmonitor.DefaultRPCMetadataExtractor, "")
		p.contextStore = contextstore.NewContextStore("./base")
		mockcls := mock_cgnetcls.NewMockCgroupnetcls(ctrl)
		p.netcls = mockcls

		Convey("When I get a destroy event with no PUID", func() {
			event := &rpcmonitor.EventInfo{
				PUID: "",
			}
			Convey("I should get an error", func() {
				err := p.Destroy(event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get destroy event without the Trireme Prefix", func() {
			event := &rpcmonitor.EventInfo{
				PUID: "/blah/blah",
			}
			Convey("It should be ignored", func() {
				err := p.Destroy(event)
				So(err, ShouldBeNil)
			})
		})

		Convey("When I get a destroy event that is valid", func() {
			event := &rpcmonitor.EventInfo{
				PUID: "/trireme/1234",
			}
			mockcls.EXPECT().Deletebasepath(gomock.Any()).Return(true)
			mockcls.EXPECT().DeleteCgroup(gomock.Any()).Return(nil)

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
		p := testLinuxProcessor(&collector.DefaultCollector{}, puHandler, rpcmonitor.DefaultRPCMetadataExtractor, "")

		Convey("When I get a pause event with no PUID", func() {
			event := &rpcmonitor.EventInfo{
				PUID: "",
			}
			Convey("I should get an error", func() {
				err := p.Pause(event)
				So(err, ShouldNotBeNil)
			})
		})

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
		p := testLinuxProcessor(&collector.DefaultCollector{}, puHandler, rpcmonitor.DefaultRPCMetadataExtractor, "")

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
				puHandler.EXPECT().SetPURuntime(gomock.Any(), gomock.Any()).Return(fmt.Errorf("Error"))
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

				puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any()).Return(fmt.Errorf("Error"))
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

				mockcls.EXPECT().Creategroup(gomock.Any()).Return(fmt.Errorf("error"))
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
