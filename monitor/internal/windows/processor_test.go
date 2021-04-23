// +build windows

package windowsmonitor

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/config"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/extractors"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/policy/mockpolicy"
)

func testWindowsProcessor(puHandler policy.Resolver) *windowsProcessor {
	w := New(context.Background())
	w.SetupHandlers(&config.ProcessorConfig{
		Collector: &collector.DefaultCollector{},
		Policy:    puHandler,
	})
	if err := w.SetupConfig(nil, &Config{
		EventMetadataExtractor: extractors.DefaultHostMetadataExtractor,
	}); err != nil {
		return nil
	}
	return w.proc
}

func TestCreate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a valid processor", t, func() {
		puHandler := mockpolicy.NewMockResolver(ctrl)

		p := testWindowsProcessor(puHandler)

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

		p := testWindowsProcessor(puHandler)

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

	Convey("Given a valid processor", t, func() {
		puHandler := mockpolicy.NewMockResolver(ctrl)

		p := testWindowsProcessor(puHandler)

		Convey("When I get a destroy event that is valid", func() {
			event := &common.EventInfo{
				PUID: "1234",
			}

			puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			Convey("I should get the status of the upstream function", func() {
				err := p.Destroy(context.Background(), event)
				So(err, ShouldBeNil)
			})
		})

		Convey("When I get a destroy event that is valid for hostpu", func() {
			event := &common.EventInfo{
				PUID:               "123",
				HostService:        true,
				NetworkOnlyTraffic: true,
			}

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

		p := testWindowsProcessor(puHandler)

		Convey("When I get a pause event that is valid", func() {
			event := &common.EventInfo{
				PUID: "/trireme/1234",
			}

			Convey("I should get the status of the upstream function", func() {
				err := p.Pause(context.Background(), event)
				So(err, ShouldNotBeNil) // Pause does nothing on Windows
			})
		})
	})
}

func TestStart(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a valid processor", t, func() {
		puHandler := mockpolicy.NewMockResolver(ctrl)
		p := testWindowsProcessor(puHandler)

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

		Convey("When I get a start event and the runtime options don't have a mark value", func() {
			event := &common.EventInfo{
				Name:      "PU",
				PID:       1,
				PUID:      "12345",
				EventType: common.EventStop,
				PUType:    common.LinuxProcessPU,
			}

			Convey("I should not get an error ", func() {
				puHandler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2).Return(nil)
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
		p := testWindowsProcessor(puHandler)

		Convey("When I get a resync event ", func() {
			event := &common.EventInfo{
				Name:      "PU",
				PID:       1,
				PUID:      "12345",
				EventType: common.EventStart,
				PUType:    common.LinuxProcessPU,
			}

			Convey("I should not get an error ", func() {
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
