package rpcmonitor

import (
	"encoding/json"
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"testing"
	"time"

	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/contextstore"
	"github.com/aporeto-inc/trireme/monitor/contextstore/mock"
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
	MonitorProcessor
}

func TestNewRPCMonitor(t *testing.T) {
	cstore := contextstore.NewCustomContextStore("/tmp")
	Convey("When we try to instantiate a new monitor", t, func() {

		Convey("If we start with invalid rpc address", func() {
			_, err := NewRPCMonitor("", nil)
			Convey("It should fail ", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If we start with an RPC address that exists", func() {

			os.Create("./testfile") // nolint : errcheck
			contextStorePath = "./base"
			_, err := NewRPCMonitor("./testfile", nil)
			Convey("I should get no error and the file is removed", func() {
				So(err, ShouldBeNil)
				_, ferr := os.Stat("./testfile")
				So(ferr, ShouldNotBeNil)
			})
		})

		Convey("If we start with valid parameters", func() {
			mon, err := NewRPCMonitor("/tmp/monitor.sock", nil)
			mon.contextstore = cstore
			Convey("It should succeed", func() {
				So(err, ShouldBeNil)
				So(mon.rpcAddress, ShouldResemble, "/tmp/monitor.sock")
				So(mon.monitorServer, ShouldNotBeNil)
				So(mon.contextstore, ShouldNotBeNil)
			})
		})
	})
}

func TestRegisterProcessor(t *testing.T) {
	cstore := contextstore.NewCustomContextStore("/tmp")
	Convey("Given a new rpc monitor", t, func() {
		mon, _ := NewRPCMonitor(testRPCAddress, nil)
		mon.contextstore = cstore
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

	contextstore := mock_contextstore.NewMockContextStore(ctrl)

	Convey("When we start an rpc processor ", t, func() {

		Convey("If we can't access the context store", func() {
			contextstore.EXPECT().WalkStore().Return(nil, fmt.Errorf("Error"))
			testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil)
			testRPCMonitor.contextstore = contextstore

			err := testRPCMonitor.Start()
			Convey("It should fail", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When the socket is busy", func() {
			clist := make(chan string, 1)
			clist <- ""

			contextstore.EXPECT().WalkStore().Return(clist, nil)
			testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil)
			testRPCMonitor.contextstore = contextstore

			go starttestserver()
			time.Sleep(1 * time.Second)
			defer stoptestserver()
			err := testRPCMonitor.Start()
			Convey("It should fail ", func() {
				So(err, ShouldNotBeNil)
			})
			stoptestserver()
		})

		Convey("When we discover invalid context we ignore the errors", func() {
			contextlist := make(chan string, 2)
			contextlist <- "test1"
			contextlist <- ""

			contextstore.EXPECT().WalkStore().Return(contextlist, nil)
			contextstore.EXPECT().GetContextInfo("/test1").Return(nil, fmt.Errorf("Invalid Context"))

			testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil)
			testRPCMonitor.contextstore = contextstore

			Convey("Start server returns no error", func() {
				starerr := testRPCMonitor.Start()
				So(starerr, ShouldBeNil)
				testRPCMonitor.Stop() // nolint
			})
		})

		Convey("When we discover invalid json we ignore it", func() {
			contextlist := make(chan string, 2)
			contextlist <- "test1"
			contextlist <- ""

			contextstore.EXPECT().WalkStore().Return(contextlist, nil)
			contextstore.EXPECT().GetContextInfo("/test1").Return([]byte("{PUType: 1,EventType:start,PUID:/test1,Name:nginx.service,Tags:{@port:80,443,app:web},PID:15691,IPs:null}"), nil)
			contextstore.EXPECT().RemoveContext("/test1").Return(nil)

			testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil)
			testRPCMonitor.contextstore = contextstore

			Convey("Start server returns no error", func() {
				starterr := testRPCMonitor.Start()
				So(starterr, ShouldBeNil)
				testRPCMonitor.Stop() //nolint
			})
		})

		Convey("When we discover invalid json and we can't remove the bad context", func() {
			contextlist := make(chan string, 2)
			contextlist <- "test1"
			contextlist <- ""

			contextstore.EXPECT().WalkStore().Return(contextlist, nil)
			contextstore.EXPECT().GetContextInfo("/test1").Return([]byte("{PUType: 1,EventType:start,PUID:/test1,Name:nginx.service,Tags:{@port:80,443,app:web},PID:15691,IPs:null}"), nil)
			contextstore.EXPECT().RemoveContext("/test1").Return(fmt.Errorf("Error"))

			testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil)
			testRPCMonitor.contextstore = contextstore

			Convey("Start server returns no error", func() {
				starterr := testRPCMonitor.Start()
				So(starterr, ShouldNotBeNil)
			})
		})

		Convey("When we discover valid context", func() {
			contextlist := make(chan string, 2)
			contextlist <- "test1"
			contextlist <- ""

			eventInfo := &EventInfo{
				EventType: monitor.EventCreate,
				PUType:    constants.LinuxProcessPU,
				PUID:      "MyPU",
				Name:      "testservice",
				Tags:      nil,
				PID:       "12345",
				IPs:       nil,
			}

			j, _ := json.Marshal(eventInfo)
			contextstore.EXPECT().WalkStore().Return(contextlist, nil)
			contextstore.EXPECT().GetContextInfo("/test1").Return(j, nil)

			testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil)
			testRPCMonitor.contextstore = contextstore
			processor := NewMockMonitorProcessor(ctrl)
			//processor.EXPECT().Start(gomock.Any()).Return(nil)
			rerr := testRPCMonitor.RegisterProcessor(constants.LinuxProcessPU, processor)
			So(rerr, ShouldBeNil)

			Convey("Start server returns no error", func() {
				starerr := testRPCMonitor.Start()
				So(starerr, ShouldBeNil)
				testRPCMonitor.Stop() //nolint
			})

		})

	})
}

func TestHandleEvent(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	contextstore := mock_contextstore.NewMockContextStore(ctrl)

	Convey("Given an RPC monitor", t, func() {
		contextlist := make(chan string, 2)
		contextlist <- "test1"
		contextlist <- ""

		contextstore.EXPECT().WalkStore().Return(contextlist, nil)
		contextstore.EXPECT().GetContextInfo("/test1").Return(nil, fmt.Errorf("Invalid Context"))

		testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil)
		testRPCMonitor.contextstore = contextstore
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
