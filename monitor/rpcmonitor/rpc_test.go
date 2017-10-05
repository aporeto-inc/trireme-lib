package rpcmonitor

import (
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"testing"
	"time"

	"github.com/aporeto-inc/mock/gomock"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/monitor"
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
	MonitorProcessor
}

func TestNewRPCMonitor(t *testing.T) {
	Convey("When we try to instantiate a new monitor", t, func() {

		Convey("If we start with invalid rpc address", func() {
			_, err := NewRPCMonitor("", nil)
			Convey("It should fail ", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If we start with an RPC address that exists", func() {

			os.Create("./testfile") // nolint : errcheck
			_, err := NewRPCMonitor("./testfile", nil)
			Convey("I should get no error and the file is removed", func() {
				So(err, ShouldBeNil)
				_, ferr := os.Stat("./testfile")
				So(ferr, ShouldNotBeNil)
			})
		})

		Convey("If we start with valid parameters", func() {
			mon, err := NewRPCMonitor("/tmp/monitor.sock", nil)
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
		mon, _ := NewRPCMonitor(testRPCAddress, nil)
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

			testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil)

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

func TestHandleEvent(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given an RPC monitor", t, func() {
		contextlist := make(chan string, 2)
		contextlist <- "test1"
		contextlist <- ""

		testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil)

		monerr := testRPCMonitor.Start()
		So(monerr, ShouldBeNil)

		Convey("If we receive an event with wrong type", func() {
			eventInfo := &EventInfo{
				EventType: "",
			}

			err := testRPCMonitor.monitorServer.HandleEvent(eventInfo, &RPCResponse{})
			Convey("We should get an error", func() {
				So(err, ShouldNotBeNil)
				testRPCMonitor.Stop() // nolint
			})
		})

		Convey("If we receive an event with no registered processor", func() {
			eventInfo := &EventInfo{
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

			processor := NewMockMonitorProcessor(ctrl)
			processor.EXPECT().Stop(gomock.Any()).Return(nil)
			monerr := testRPCMonitor.RegisterProcessor(constants.LinuxProcessPU, processor)
			So(monerr, ShouldBeNil)

			eventInfo := &EventInfo{
				EventType: monitor.EventStop,
				PUType:    constants.LinuxProcessPU,
			}

			err := testRPCMonitor.monitorServer.HandleEvent(eventInfo, &RPCResponse{})
			Convey("We should get no error", func() {
				So(err, ShouldBeNil)
				testRPCMonitor.Stop() // nolint
			})
		})

		Convey("If we receive an event that fails processing", func() {

			processor := NewMockMonitorProcessor(ctrl)
			processor.EXPECT().Create(gomock.Any()).Return(fmt.Errorf("Error"))
			monerr := testRPCMonitor.RegisterProcessor(constants.LinuxProcessPU, processor)
			So(monerr, ShouldBeNil)

			eventInfo := &EventInfo{
				EventType: monitor.EventCreate,
				PUType:    constants.LinuxProcessPU,
			}

			err := testRPCMonitor.monitorServer.HandleEvent(eventInfo, &RPCResponse{})
			Convey("We should get an error", func() {
				So(err, ShouldNotBeNil)
				testRPCMonitor.Stop() // nolint
			})
		})
	})
}

func TestDefaultRPCMetadataExtractor(t *testing.T) {
	Convey("Given an event", t, func() {
		Convey("If the event name is empty", func() {
			eventInfo := &EventInfo{
				EventType: monitor.EventStop,
				PUType:    constants.LinuxProcessPU,
			}

			Convey("The default extractor must return an error ", func() {
				_, err := DefaultRPCMetadataExtractor(eventInfo)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If the event PID is empty", func() {
			eventInfo := &EventInfo{
				Name:      "PU",
				EventType: monitor.EventStop,
				PUType:    constants.LinuxProcessPU,
			}

			Convey("The default extractor must return an error ", func() {
				_, err := DefaultRPCMetadataExtractor(eventInfo)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If the event PUID is empty", func() {
			eventInfo := &EventInfo{
				Name:      "PU",
				PID:       "1234",
				EventType: monitor.EventStop,
				PUType:    constants.LinuxProcessPU,
			}

			Convey("The default extractor must return an error ", func() {
				_, err := DefaultRPCMetadataExtractor(eventInfo)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If the PID is not a number", func() {
			eventInfo := &EventInfo{
				Name:      "PU",
				PID:       "abcera",
				PUID:      "12345",
				EventType: monitor.EventStop,
				PUType:    constants.LinuxProcessPU,
			}

			Convey("The default extractor must return an error ", func() {
				_, err := DefaultRPCMetadataExtractor(eventInfo)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If all parameters are correct", func() {
			eventInfo := &EventInfo{
				Name:      "PU",
				PID:       "1",
				PUID:      "12345",
				EventType: monitor.EventStop,
				PUType:    constants.LinuxProcessPU,
			}

			Convey("The default extractor must return no error ", func() {
				runtime, err := DefaultRPCMetadataExtractor(eventInfo)
				So(err, ShouldBeNil)
				So(runtime, ShouldNotBeNil)
			})
		})

	})
}
