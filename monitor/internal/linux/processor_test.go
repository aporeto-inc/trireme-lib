package linuxmonitor

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"testing"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/policy/mockpolicy"
	"go.aporeto.io/trireme-lib/utils/cgnetcls/mockcgnetcls"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
)

func testLinuxProcessor(puHandler policy.Resolver) *linuxProcessor {
	l := New()
	l.SetupHandlers(&config.ProcessorConfig{
		Collector: &collector.DefaultCollector{},
		Policy:    puHandler,
	})
	if err := l.SetupConfig(nil, &Config{
		EventMetadataExtractor: extractors.DefaultHostMetadataExtractor,
		StoredPath:             "/tmp",
		ReleasePath:            "./",
	}); err != nil {
		return nil
	}
	return l.proc
}

func TestCreate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a valid processor", t, func() {
		puHandler := mockpolicy.NewMockResolver(ctrl)

		p := testLinuxProcessor(puHandler)

		Convey("When I try a create event with invalid PU ID, ", func() {
			event := &common.EventInfo{
				PUID: "/@#$@",
			}
			Convey("I should get an error", func() {
				err := p.Create(context.Background(), event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get a create event that is valid", func() {
			event := &common.EventInfo{
				PUID: "1234",
			}
			Convey("I should get an error - create not supported", func() {
				err := p.Create(context.Background(), event)
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestStop(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a valid processor", t, func() {
		puHandler := mockpolicy.NewMockResolver(ctrl)

		p := testLinuxProcessor(puHandler)
		p.netcls = mockcgnetcls.NewMockCgroupnetcls(ctrl)

		Convey("When I get a stop event that is valid", func() {
			event := &common.EventInfo{
				PUID: "/trireme/1234",
			}

			puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			Convey("I should get the status of the upstream function", func() {
				err := p.Stop(context.Background(), event)
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
		puHandler := mockpolicy.NewMockResolver(ctrl)

		p := testLinuxProcessor(puHandler)
		mockcls := mockcgnetcls.NewMockCgroupnetcls(ctrl)
		p.netcls = mockcls

		Convey("When I get a destroy event that is valid", func() {
			event := &common.EventInfo{
				PUID: "/trireme/1234",
			}
			mockcls.EXPECT().DeleteCgroup(gomock.Any()).Return(nil)

			puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			Convey("I should get the status of the upstream function", func() {
				err := p.Destroy(context.Background(), event)
				So(err, ShouldBeNil)
			})
		})

	})
}

func TestPause(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a valid processor", t, func() {
		puHandler := mockpolicy.NewMockResolver(ctrl)

		p := testLinuxProcessor(puHandler)

		Convey("When I get a pause event that is valid", func() {
			event := &common.EventInfo{
				PUID: "/trireme/1234",
			}

			puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			Convey("I should get the status of the upstream function", func() {
				err := p.Pause(context.Background(), event)
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestStart(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a valid processor", t, func() {
		puHandler := mockpolicy.NewMockResolver(ctrl)
		p := testLinuxProcessor(puHandler)

		Convey("When I get a start event with no PUID", func() {
			event := &common.EventInfo{
				PUID: "",
			}
			Convey("I should get an error", func() {
				err := p.Start(context.Background(), event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get a start event that is valid that fails on the generation of PU ID", func() {
			event := &common.EventInfo{
				Name: "^^^",
			}
			Convey("I should get an error", func() {
				err := p.Start(context.Background(), event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get a start event that is valid that fails on the metadata extractor", func() {
			event := &common.EventInfo{
				Name: "service",
				Tags: []string{"badtag"},
			}
			Convey("I should get an error", func() {
				err := p.Start(context.Background(), event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get a start event and the upstream returns an error ", func() {
			event := &common.EventInfo{
				Name:      "PU",
				PID:       1,
				PUID:      "12345",
				EventType: common.EventStart,
				PUType:    common.LinuxProcessPU,
			}
			Convey("I should get an error ", func() {
				puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("error"))
				err := p.Start(context.Background(), event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get a start event and create group fails ", func() {
			event := &common.EventInfo{
				Name:      "PU",
				PID:       1,
				PUID:      "12345",
				EventType: common.EventStop,
				PUType:    common.LinuxProcessPU,
			}

			mockcls := mockcgnetcls.NewMockCgroupnetcls(ctrl)
			p.netcls = mockcls

			Convey("I should get an error ", func() {
				puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2).Return(nil)
				mockcls.EXPECT().Creategroup(gomock.Any()).Return(errors.New("error"))

				err := p.Start(context.Background(), event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get a start event and the runtime options don't have a mark value", func() {
			event := &common.EventInfo{
				Name:      "PU",
				PID:       1,
				PUID:      "12345",
				EventType: common.EventStop,
				PUType:    common.LinuxProcessPU,
			}

			mockcls := mockcgnetcls.NewMockCgroupnetcls(ctrl)
			p.netcls = mockcls

			Convey("I should not get an error ", func() {
				puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2).Return(nil)
				mockcls.EXPECT().Creategroup(gomock.Any()).Return(nil)
				mockcls.EXPECT().AssignMark(gomock.Any(), gomock.Any()).Return(nil)
				mockcls.EXPECT().AddProcess(gomock.Any(), gomock.Any())
				err := p.Start(context.Background(), event)
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestResync(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a valid processor", t, func() {
		puHandler := mockpolicy.NewMockResolver(ctrl)
		p := testLinuxProcessor(puHandler)

		Convey("When I get a resync event ", func() {
			event := &common.EventInfo{
				Name:      "PU",
				PID:       1,
				PUID:      "12345",
				EventType: common.EventStart,
				PUType:    common.LinuxProcessPU,
			}

			mockcls := mockcgnetcls.NewMockCgroupnetcls(ctrl)
			p.netcls = mockcls

			Convey("I should not get an error ", func() {
				mockcls.EXPECT().ListAllCgroups(gomock.Any()).Return([]string{"cgroup"})
				mockcls.EXPECT().ListCgroupProcesses(gomock.Any()).Return([]string{"procs"}, nil)
				mockcls.EXPECT().Creategroup(gomock.Any()).Return(nil)
				mockcls.EXPECT().AssignMark(gomock.Any(), gomock.Any()).Return(nil)
				puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				err := p.Resync(context.Background(), event)
				So(err, ShouldBeNil)
			})
		})

		Convey("When I get a resync event with no croup process", func() {
			event := &common.EventInfo{
				Name:      "PU",
				PID:       1,
				PUID:      "12345",
				EventType: common.EventStart,
				PUType:    common.LinuxProcessPU,
			}

			mockcls := mockcgnetcls.NewMockCgroupnetcls(ctrl)
			p.netcls = mockcls

			Convey("I should not get an error ", func() {
				mockcls.EXPECT().ListAllCgroups(gomock.Any()).Return([]string{"cgroup"})
				mockcls.EXPECT().ListCgroupProcesses(gomock.Any()).Return([]string{}, nil)
				mockcls.EXPECT().DeleteCgroup(gomock.Any()).Return(nil)
				err := p.Resync(context.Background(), event)
				So(err, ShouldBeNil)
			})
		})

		Convey("When I get a resync event for hostservice", func() {
			event := &common.EventInfo{
				Name:               "PU",
				PID:                1,
				PUID:               "12345",
				EventType:          common.EventStart,
				HostService:        true,
				NetworkOnlyTraffic: true,
				PUType:             common.LinuxProcessPU,
			}

			Convey("I should not get an error ", func() {
				puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				err := p.Resync(context.Background(), event)
				So(err, ShouldBeNil)
			})
		})
	})
}
