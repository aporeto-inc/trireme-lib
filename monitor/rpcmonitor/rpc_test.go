package rpcmonitor

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"testing"
	"time"

	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/monitor"
	"github.com/aporeto-inc/trireme-lib/monitor/eventinfo"
	"github.com/aporeto-inc/trireme-lib/monitor/processor"
	"github.com/aporeto-inc/trireme-lib/monitor/processor/mock"
	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
)

// Util functions to start test RPC server
// This will always return success
var listener net.UnixListener
var testRPCAddress = "/tmp/test.sock"

func starttestserver() {

	os.Remove(testRPCAddress) // nolint
	rpcServer := rpc.NewServer()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{
		Name: testRPCAddress,
		Net:  "unix",
	})

	if err != nil {
		fmt.Println(err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			break
		}
		rpcServer.ServeCodec(jsonrpc.NewServerCodec(conn))
	}
	os.Remove(testRPCAddress) // nolint
}

func stoptestserver() {
	listener.Close()          //nolint
	os.Remove(testRPCAddress) //nolint

}

type CustomProcessor struct {
	processor.EventProcessor
}

func TestNewRPCMonitor(t *testing.T) {
	Convey("When we try to instantiate a new monitor", t, func() {

		Convey("If we start with invalid rpc address", func() {
			_, err := NewRPCMonitor("", nil, false)
			Convey("It should fail ", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If we start with an RPC address that exists", func() {

			os.Create("./testfile") // nolint : errcheck
			_, err := NewRPCMonitor("./testfile", nil, false)
			Convey("I should get no error and the file is removed", func() {
				So(err, ShouldBeNil)
				_, ferr := os.Stat("./testfile")
				So(ferr, ShouldNotBeNil)
			})
		})

		Convey("If we start with valid parameters", func() {
			mon, err := NewRPCMonitor("/tmp/monitor.sock", nil, false)
			Convey("It should succeed", func() {
				So(err, ShouldBeNil)
				So(mon.rpcAddress, ShouldResemble, "/tmp/monitor.sock")
				So(mon.monitorServer, ShouldNotBeNil)
			})
		})
	})
}

func TestRegisterProcessor(t *testing.T) {

	Convey("Given a new rpc monitor", t, func() {
		mon, _ := NewRPCMonitor(testRPCAddress, nil, false)
		Convey("When I try to register a new processor", func() {
			processor := &CustomProcessor{}
			err := mon.RegisterProcessor(constants.LinuxProcessPU, processor)
			Convey("Then it should succeed", func() {
				So(err, ShouldBeNil)
				So(mon.monitorServer.handlers, ShouldNotBeNil)
				So(mon.monitorServer.handlers[constants.LinuxProcessPU], ShouldNotBeNil)
			})
		})

		Convey("When I try to register the same processor twice", func() {
			processor := &CustomProcessor{}
			monerr := mon.RegisterProcessor(constants.LinuxProcessPU, processor)
			So(monerr, ShouldBeNil)
			err := mon.RegisterProcessor(constants.LinuxProcessPU, processor)
			Convey("Then it should fail", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestStart(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When we start an rpc processor ", t, func() {

		Convey("When the socket is busy", func() {
			clist := make(chan string, 1)
			clist <- ""

			testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil, false)

			go starttestserver()
			time.Sleep(1 * time.Second)
			defer stoptestserver()
			err := testRPCMonitor.Start()
			Convey("It should fail ", func() {
				So(err, ShouldNotBeNil)
			})
			stoptestserver()
		})
	})
}

// TODO: remove nolint
// nolint
func TestHandleEvent(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	dummyPUPath := "/var/run/trireme/linux/1234"
	Convey("Given an RPC monitor", t, func() {
		contextlist := make(chan string, 2)
		contextlist <- "test1"
		contextlist <- ""

		testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil, false)

		monerr := testRPCMonitor.Start()
		So(monerr, ShouldBeNil)

		Convey("If we receive an event with wrong type", func() {
			eventInfo := &eventinfo.EventInfo{
				EventType: "",
			}

			err := testRPCMonitor.monitorServer.HandleEvent(eventInfo, &RPCResponse{})
			Convey("We should get an error", func() {
				So(err, ShouldNotBeNil)
				testRPCMonitor.Stop() // nolint
			})
		})

		Convey("If we receive an event with no registered processor", func() {
			eventInfo := &eventinfo.EventInfo{
				EventType: monitor.EventCreate,
				PUType:    constants.LinuxProcessPU,
			}

			err := testRPCMonitor.monitorServer.HandleEvent(eventInfo, &RPCResponse{})
			Convey("We should get an error", func() {
				So(err, ShouldNotBeNil)
				testRPCMonitor.Stop() //nolint
			})
		})

		Convey("If we receive a good event with a registered processor", func() {

			processor := mockprocessor.NewMockEventProcessor(ctrl)
			processor.EXPECT().Start(gomock.Any()).Return(nil)
			fmt.Printf("Calling Register %v\n", processor)
			monerr := testRPCMonitor.RegisterProcessor(constants.LinuxProcessPU, processor)
			So(monerr, ShouldBeNil)

			eventInfo := &eventinfo.EventInfo{
				EventType: monitor.EventStart,
				PUType:    constants.LinuxProcessPU,
				PUID:      "/trireme/1234",
				PID:       "123",
			}

			ioutil.WriteFile(dummyPUPath, []byte{}, 0644) //nolint

			err := testRPCMonitor.monitorServer.HandleEvent(eventInfo, &RPCResponse{})
			Convey("We should get no error", func() {

				So(err, ShouldBeNil)
				testRPCMonitor.Stop() // nolint
			})
		})

		Convey("If we receive an event that fails processing", func() {

			processor := mockprocessor.NewMockEventProcessor(ctrl)
			processor.EXPECT().Create(gomock.Any()).Return(fmt.Errorf("Error"))
			monerr := testRPCMonitor.RegisterProcessor(constants.LinuxProcessPU, processor)
			So(monerr, ShouldBeNil)

			eventInfo := &eventinfo.EventInfo{
				EventType: monitor.EventCreate,
				PUType:    constants.LinuxProcessPU,
				PID:       "123",
			}

			err := testRPCMonitor.monitorServer.HandleEvent(eventInfo, &RPCResponse{})
			Convey("We should get an error", func() {
				So(err, ShouldNotBeNil)
				testRPCMonitor.Stop() // nolint
			})
		})
	})
}

func TestDefaultEventMetadataExtractor(t *testing.T) {
	Convey("Given an event", t, func() {
		Convey("If the event name is empty", func() {
			eventInfo := &eventinfo.EventInfo{
				EventType: monitor.EventStop,
				PUType:    constants.LinuxProcessPU,
			}

			Convey("The default extractor must return an error ", func() {
				_, err := DefaultEventMetadataExtractor(eventInfo)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If the event PID is empty", func() {
			eventInfo := &eventinfo.EventInfo{
				Name:      "PU",
				EventType: monitor.EventStop,
				PUType:    constants.LinuxProcessPU,
			}

			Convey("The default extractor must return an error ", func() {
				_, err := DefaultEventMetadataExtractor(eventInfo)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If the PID is not a number", func() {
			eventInfo := &eventinfo.EventInfo{
				Name:      "PU",
				PID:       "abcera",
				PUID:      "12345",
				EventType: monitor.EventStop,
				PUType:    constants.LinuxProcessPU,
			}

			Convey("The default extractor must return an error ", func() {
				_, err := DefaultEventMetadataExtractor(eventInfo)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If all parameters are correct", func() {
			eventInfo := &eventinfo.EventInfo{
				Name:      "PU",
				PID:       "1",
				PUID:      "12345",
				EventType: monitor.EventStop,
				PUType:    constants.LinuxProcessPU,
			}

			Convey("The default extractor must return no error ", func() {
				runtime, err := DefaultEventMetadataExtractor(eventInfo)
				So(err, ShouldBeNil)
				So(runtime, ShouldNotBeNil)
			})
		})

	})
}
