package linuxmonitor

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/monitor/config"
	"github.com/aporeto-inc/trireme-lib/monitor/extractors"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/policy/mock"
	"github.com/aporeto-inc/trireme-lib/utils/cgnetcls/mock"
	"github.com/aporeto-inc/trireme-lib/utils/contextstore/mock"
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
	return l.(*linuxMonitor).proc
}

func TestCreate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a valid processor", t, func() {
		puHandler := mockpolicy.NewMockResolver(ctrl)
		store := mockcontextstore.NewMockContextStore(ctrl)

		p := testLinuxProcessor(puHandler)
		p.contextStore = store

		Convey("When I try a create event with invalid PU ID, ", func() {
			event := &common.EventInfo{
				PUID: "/@#$@",
			}
			Convey("I should get an error", func() {
				err := p.Create(event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get a create event that is valid", func() {
			event := &common.EventInfo{
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
		puHandler := mockpolicy.NewMockResolver(ctrl)
		store := mockcontextstore.NewMockContextStore(ctrl)

		p := testLinuxProcessor(puHandler)
		p.contextStore = store
		p.netcls = mockcgnetcls.NewMockCgroupnetcls(ctrl)

		Convey("When I get a stop event that is valid", func() {
			event := &common.EventInfo{
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
		puHandler := mockpolicy.NewMockResolver(ctrl)
		store := mockcontextstore.NewMockContextStore(ctrl)

		p := testLinuxProcessor(puHandler)
		p.contextStore = store
		p.contextStore = store
		mockcls := mockcgnetcls.NewMockCgroupnetcls(ctrl)
		p.netcls = mockcls

		Convey("When I get a destroy event that is valid", func() {
			event := &common.EventInfo{
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
		puHandler := mockpolicy.NewMockResolver(ctrl)
		store := mockcontextstore.NewMockContextStore(ctrl)

		p := testLinuxProcessor(puHandler)
		p.contextStore = store

		Convey("When I get a pause event that is valid", func() {
			event := &common.EventInfo{
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
		puHandler := mockpolicy.NewMockResolver(ctrl)
		store := mockcontextstore.NewMockContextStore(ctrl)

		p := testLinuxProcessor(puHandler)
		p.contextStore = store

		Convey("When I get a start event with no PUID", func() {
			event := &common.EventInfo{
				PUID: "",
			}
			Convey("I should get an error", func() {
				err := p.Start(event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get a start event that is valid that fails on the metadata extractor", func() {
			event := &common.EventInfo{
				Name: "PU",
			}
			Convey("I should get an error", func() {
				err := p.Start(event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get a start event and setting the PU runtime fails", func() {
			event := &common.EventInfo{
				Name:      "PU",
				PID:       "1",
				PUID:      "12345",
				EventType: common.EventStop,
				PUType:    common.LinuxProcessPU,
			}
			Convey("I should get an error ", func() {
				puHandler.EXPECT().CreatePURuntime(gomock.Any(), gomock.Any()).Return(fmt.Errorf("Error"))
				err := p.Start(event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get a start event and the upstream returns an error ", func() {
			event := &common.EventInfo{
				Name:      "PU",
				PID:       "1",
				PUID:      "12345",
				EventType: common.EventStop,
				PUType:    common.LinuxProcessPU,
			}
			Convey("I should get an error ", func() {
				puHandler.EXPECT().CreatePURuntime(gomock.Any(), gomock.Any()).Return(nil)

				puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any()).Return(errors.New("error"))
				err := p.Start(event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get a start event and create group fails ", func() {
			event := &common.EventInfo{
				Name:      "PU",
				PID:       "1",
				PUID:      "12345",
				EventType: common.EventStop,
				PUType:    common.LinuxProcessPU,
			}

			mockcls := mockcgnetcls.NewMockCgroupnetcls(ctrl)
			p.netcls = mockcls

			Convey("I should get an error ", func() {
				puHandler.EXPECT().CreatePURuntime(gomock.Any(), gomock.Any()).Return(nil)
				puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any()).Return(nil)

				mockcls.EXPECT().Creategroup(gomock.Any()).Return(errors.New("error"))
				err := p.Start(event)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I get a start event and the runtime options don't have a mark value", func() {
			event := &common.EventInfo{
				Name:      "PU",
				PID:       "1",
				PUID:      "12345",
				EventType: common.EventStop,
				PUType:    common.LinuxProcessPU,
			}

			mockcls := mockcgnetcls.NewMockCgroupnetcls(ctrl)
			p.netcls = mockcls

			Convey("I should not get an error ", func() {
				puHandler.EXPECT().CreatePURuntime(gomock.Any(), gomock.Any()).Return(nil)
				puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any()).Return(nil)

				mockcls.EXPECT().Creategroup(gomock.Any()).Return(nil)
				mockcls.EXPECT().AssignMark(gomock.Any(), gomock.Any()).Return(nil)
				mockcls.EXPECT().AddProcess(gomock.Any(), gomock.Any())
				store.EXPECT().Store(gomock.Any(), gomock.Any())
				err := p.Start(event)
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
		store := mockcontextstore.NewMockContextStore(ctrl)

		p := testLinuxProcessor(puHandler)
		p.contextStore = store

		cls := mockcgnetcls.NewMockCgroupnetcls(ctrl)
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

			storedContext := StoredContext{
				EventInfo: &common.EventInfo{
					PID:       "1",
					PUType:    common.LinuxProcessPU,
					EventType: common.EventStart,
					PUID:      "/test1",
				},
			}

			store.EXPECT().Walk().Return(contextlist, nil)
			store.EXPECT().Retrieve("/test1", gomock.Any()).SetArg(1, storedContext).Return(nil)
			// store.EXPECT().Remove("/test1").Return(nil)

			Convey("Start server returns no error", func() {
				err := p.ReSync(nil)
				So(err, ShouldBeNil)
			})
		})
	})
}
