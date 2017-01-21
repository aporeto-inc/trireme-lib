package rpcmonitor

import (
	"errors"
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"testing"
	"time"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/mock"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/contextstore/mock"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls/mock"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
)

//Util functions to start test RPC server
//This will always return sucess
var runserver bool
var listener net.UnixListener

var testRPCAddress = "/tmp/test.sock"

func starttestserver() {

	rpcServer := rpc.NewServer()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{
		Name: testRPCAddress,
		Net:  "unix",
	})

	if err != nil {
		fmt.Println(err)
	}
	os.Chmod(testRPCAddress, 0766)
	runserver = true
	for {
		conn, err := listener.Accept()
		if err != nil {
			break
		}
		rpcServer.ServeCodec(jsonrpc.NewServerCodec(conn))
	}
	os.Remove(testRPCAddress)

}

func stoptestserver() {
	listener.Close()
	os.Remove(testRPCAddress)

}

type CustomPolicyResolver struct {
	monitor.ProcessingUnitsHandler
}

func TestStart(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	netcls := mock_cgnetcls.NewMockCgroupnetcls(ctrl)
	contextstore := mock_contextstore.NewMockContextStore(ctrl)

	puHandler := &CustomPolicyResolver{}

	Convey("When listen fails rpc start should fail", t, func() {

		Convey("When we start server", func() {
			clist := make(chan string, 1)
			clist <- ""

			contextstore.EXPECT().WalkStore().Return(clist, nil)

			testRPCMonitor, err := NewRPCMonitor(testRPCAddress, nil, puHandler, nil, netcls, contextstore)
			if err != nil {
				fmt.Println(err)
				t.SkipNow()
			}
			go starttestserver()
			time.Sleep(1 * time.Second)
			defer stoptestserver()
			err = testRPCMonitor.Start()
			So(err, ShouldNotBeNil)
			//testRPCMonitor.Stop()
		})
		stoptestserver()
		Convey("When we discover invalid context we don't return an error", func() {
			contextlist := make(chan string, 2)
			contextlist <- "test1"
			contextlist <- ""
			contextstore.EXPECT().WalkStore().Return(contextlist, nil)
			contextstore.EXPECT().GetContextInfo("/test1").Return(nil, fmt.Errorf("Invalid Context"))
			testRPCMonitor, err := NewRPCMonitor(testRPCAddress, nil, puHandler, nil, netcls, contextstore)
			if err != nil {
				fmt.Println(err)
				t.SkipNow()
			}

			Convey("Start server returns no error", func() {
				starerr := testRPCMonitor.Start()
				So(starerr, ShouldBeNil)
				testRPCMonitor.Stop()
			})

		})

		Convey("When we discover valid context json unmarshals", func() {
			contextlist := make(chan string, 2)
			contextlist <- "test1"
			contextlist <- ""
			contextstore.EXPECT().WalkStore().Return(contextlist, nil)
			contextstore.EXPECT().GetContextInfo("/test1").Return([]byte("{EventType:start,PUID:/test1,Name:nginx.service,Tags:{@port:80,443,app:web},PID:15691,IPs:null}"), nil)
			testRPCMonitor, err := NewRPCMonitor(testRPCAddress, nil, puHandler, nil, netcls, contextstore)
			if err != nil {
				fmt.Println(err)
				t.SkipNow()
			}

			Convey("Start server returns no error", func() {
				starterr := testRPCMonitor.Start()
				So(starterr, ShouldBeNil)
				testRPCMonitor.Stop()
			})

		})

	})

}

func testclienthelper(eventInfo *EventInfo) error {
	response := &RPCResponse{}
	client, err := net.Dial("unix", testRPCAddress)
	if err != nil {
		fmt.Println("Error", err)
		return err
	}
	rpcClient := jsonrpc.NewClient(client)
	err = rpcClient.Call("Server.HandleEvent", eventInfo, response)
	return err

}

func TestHandleEvent(t *testing.T) {
	//Will change strategy here this function forward to too many paths will test each in their own path using handleevent as the entry point
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	netcls := mock_cgnetcls.NewMockCgroupnetcls(ctrl)
	contextstore := mock_contextstore.NewMockContextStore(ctrl)
	puHandler := mock_trireme.NewMockProcessingUnitsHandler(ctrl)
	//puHandler := &CustomPolicyResolver{}
	Convey("Testing handlevent", t, func() {
		Convey("We pass invalid contextID  eventInfo we return error", func() {
			clist := make(chan string, 1)
			clist <- ""

			contextstore.EXPECT().WalkStore().Return(clist, nil)

			testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil, puHandler, nil, netcls, contextstore)
			err := testRPCMonitor.Start()
			if err != nil {
				fmt.Println(err)
				t.SkipNow()
			}
			//CreateEvent will return an error if we cannot create context. We will use this behavior to test error paths in HandleEvent
			eventInfo := &EventInfo{
				EventType: monitor.EventCreate,
				PUID:      "", //This will cause the failure
				Name:      "testservice",
				Tags:      nil,
				PID:       "12345",
				IPs:       nil,
			}

			err = testclienthelper(eventInfo)
			So(err, ShouldNotBeNil)
			testRPCMonitor.Stop()
		})

		Convey("We pass uninitialzed eventInfo we return error", func() {
			clist := make(chan string, 1)
			clist <- ""

			contextstore.EXPECT().WalkStore().Return(clist, nil)

			testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil, puHandler, nil, netcls, contextstore)
			err := testRPCMonitor.Start()
			if err != nil {
				fmt.Println(err)
				t.SkipNow()
			}
			//CreateEvent will return an error if we cannot create context. We will use this behavior to test error paths in HandleEvent
			var eventInfo *EventInfo
			eventInfo = nil
			err = testclienthelper(eventInfo)
			So(err, ShouldNotBeNil)
			testRPCMonitor.Stop()
		})

		Convey("We pass a well formed  eventInfo we no error", func() {
			clist := make(chan string, 1)
			clist <- ""
			os.RemoveAll(testRPCAddress)
			contextstore.EXPECT().WalkStore().Return(clist, nil)
			testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil, puHandler, &collector.DefaultCollector{}, netcls, contextstore)
			err := testRPCMonitor.Start()
			if err != nil {
				fmt.Println(err)
				t.SkipNow()
			}
			//CreateEvent will return an error if we cannot create context. We will use this behavior to test error paths in HandleEvent

			eventInfo := EventInfo{
				EventType: monitor.EventCreate,
				PUID:      "/test1", //This will cause the failure
				Name:      "testservice",
				Tags:      nil,
				PID:       "12345",
				IPs:       nil,
			}
			errChan := make(chan error, 1)

			puHandler.EXPECT().HandlePUEvent("/test1", monitor.EventCreate).Return(errChan)
			errChan <- nil
			err = testclienthelper(&eventInfo)
			if err != nil {
				fmt.Println(err)
			}
			So(err, ShouldBeNil)
			testRPCMonitor.Stop()
		})

	})
}

func TestStartEvent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	netcls := mock_cgnetcls.NewMockCgroupnetcls(ctrl)
	contextstore := mock_contextstore.NewMockContextStore(ctrl)
	puHandler := mock_trireme.NewMockProcessingUnitsHandler(ctrl)
	Convey("Testing handlstartevent", t, func() {
		Convey("We pass invalid contextID  eventInfo we return error", func() {
			clist := make(chan string, 1)
			clist <- ""

			contextstore.EXPECT().WalkStore().Return(clist, nil)

			testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil, puHandler, nil, netcls, contextstore)
			err := testRPCMonitor.Start()
			if err != nil {
				fmt.Println(err)
				t.SkipNow()
			}
			//CreateEvent will return an error if we cannot create context. We will use this behavior to test error paths in HandleEvent
			eventInfo := &EventInfo{
				EventType: monitor.EventStart,
				PUID:      "", //This will cause the failure
				Name:      "testservice",
				Tags:      nil,
				PID:       "12345",
				IPs:       nil,
			}

			err = testclienthelper(eventInfo)
			So(err, ShouldNotBeNil)
			testRPCMonitor.Stop()
		})

		Convey("HandlePUEvent returns an error", func() {
			clist := make(chan string, 1)
			clist <- ""

			contextstore.EXPECT().WalkStore().Return(clist, nil)

			testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil, puHandler, &collector.DefaultCollector{}, netcls, contextstore)
			err := testRPCMonitor.Start()
			if err != nil {
				fmt.Println(err)
				t.SkipNow()
			}
			eventInfo := &EventInfo{
				EventType: monitor.EventStart,
				PUID:      "/test1", //This will cause the failure
				Name:      "testservice",
				Tags:      nil,
				PID:       "12345",
				IPs:       nil,
			}
			runtime := policy.NewPURuntime(eventInfo.Name, 12345, nil, nil, policy.ContainerPU, nil)
			puHandler.EXPECT().SetPURuntime("/test1", runtime)
			errChan := make(chan error, 1)
			puHandler.EXPECT().HandlePUEvent("/test1", monitor.EventStart).Return(errChan)
			netcls.EXPECT().Creategroup(eventInfo.PUID).MaxTimes(0)
			netcls.EXPECT().AssignMark(eventInfo.PUID, 100).MaxTimes(0)
			netcls.EXPECT().AddProcess(eventInfo.PUID, 12345).MaxTimes(0)
			errChan <- errors.New("handlePUevent error")
			err = testclienthelper(eventInfo)
			So(err, ShouldNotBeNil)
			testRPCMonitor.Stop()
		})

		Convey("Creategroup returns an error", func() {
			clist := make(chan string, 1)
			clist <- ""

			contextstore.EXPECT().WalkStore().Return(clist, nil)

			testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil, puHandler, &collector.DefaultCollector{}, netcls, contextstore)
			err := testRPCMonitor.Start()
			if err != nil {
				fmt.Println(err)
				t.SkipNow()
			}
			eventInfo := &EventInfo{
				EventType: monitor.EventStart,
				PUID:      "/test1", //This will cause the failure
				Name:      "testservice",
				Tags:      nil,
				PID:       "12345",
				IPs:       nil,
			}
			runtime := policy.NewPURuntime(eventInfo.Name, 12345, nil, nil, policy.ContainerPU, nil)
			puHandler.EXPECT().SetPURuntime("/test1", runtime)
			errChan := make(chan error, 1)
			puHandler.EXPECT().HandlePUEvent("/test1", monitor.EventStart).Return(errChan)
			netcls.EXPECT().Creategroup(eventInfo.PUID).MaxTimes(1).Return(errors.New("Creategroup error"))
			netcls.EXPECT().AssignMark(eventInfo.PUID, 100).MaxTimes(0)
			netcls.EXPECT().AddProcess(eventInfo.PUID, 12345).MaxTimes(0)
			errChan <- nil
			err = testclienthelper(eventInfo)

			So(err, ShouldNotBeNil)
			testRPCMonitor.Stop()
		})

		Convey("Assignmark returns an error", func() {
			clist := make(chan string, 1)
			clist <- ""

			contextstore.EXPECT().WalkStore().Return(clist, nil)

			testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil, puHandler, &collector.DefaultCollector{}, netcls, contextstore)
			err := testRPCMonitor.Start()
			if err != nil {
				fmt.Println(err)
				t.SkipNow()
			}
			markmap := make(map[string]string)
			markmap["@cgroup_mark"] = "100"
			var mark uint64 = 100
			eventInfo := &EventInfo{
				EventType: monitor.EventStart,
				PUID:      "/test1", //This will cause the failure
				Name:      "testservice",
				Tags:      markmap,
				PID:       "12345",
				IPs:       nil,
			}
			tags := &policy.TagsMap{Tags: make(map[string]string)}
			tags.Add("@cgroup_mark", "100")
			runtime := policy.NewPURuntime(eventInfo.Name, 12345, tags, nil, policy.ContainerPU, nil)
			puHandler.EXPECT().SetPURuntime("/test1", runtime)
			errChan := make(chan error, 1)
			puHandler.EXPECT().HandlePUEvent("/test1", monitor.EventStart).Return(errChan)
			netcls.EXPECT().Creategroup(eventInfo.PUID).MaxTimes(1).Return(nil)
			netcls.EXPECT().AssignMark(eventInfo.PUID, mark).MaxTimes(1).Return(errors.New("AssignMark Error"))
			netcls.EXPECT().DeleteCgroup(eventInfo.PUID).Return(nil)
			netcls.EXPECT().AddProcess(eventInfo.PUID, 12345).MaxTimes(0)
			errChan <- nil
			err = testclienthelper(eventInfo)

			So(err, ShouldNotBeNil)
			testRPCMonitor.Stop()
		})

		// Convey("handleStartEvent suceeds", func() {
		// 	clist := make(chan string, 1)
		// 	clist <- ""
		//
		// 	contextstore.EXPECT().WalkStore().Return(clist, nil)
		//
		// 	testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil, puHandler, &collector.DefaultCollector{}, netcls, contextstore)
		// 	err := testRPCMonitor.Start()
		// 	if err != nil {
		// 		fmt.Println(err)
		// 		t.SkipNow()
		// 	}
		// 	markmap := make(map[string]string)
		// 	markmap["@cgroup_mark"] = "100"
		// 	var mark uint64 = 100
		// 	eventInfo := &EventInfo{
		// 		EventType: monitor.EventStart,
		// 		PUID:      "/test1", //This will cause the failure
		// 		Name:      "testservice",
		// 		Tags:      markmap,
		// 		PID:       "12345",
		// 		IPs:       nil,
		// 	}
		// 	tags := &policy.TagsMap{Tags: make(map[string]string)}
		// 	tags.Add("@cgroup_mark", "100")
		// 	runtime := policy.NewPURuntime(eventInfo.Name, 12345, tags, nil, policy.ContainerPU, nil)
		// 	puHandler.EXPECT().SetPURuntime("/test1", runtime)
		// 	errChan := make(chan error, 1)
		// 	puHandler.EXPECT().HandlePUEvent("/test1", monitor.EventStart).Return(errChan)
		// 	netcls.EXPECT().Creategroup(eventInfo.PUID).MaxTimes(1).Return(nil)
		// 	netcls.EXPECT().AssignMark(eventInfo.PUID, mark).MaxTimes(1).Return(nil)
		// 	netcls.EXPECT().AddProcess(eventInfo.PUID, 12345).MaxTimes(1).Return(nil)
		// 	netcls.EXPECT().DeleteCgroup(eventInfo.PUID).MaxTimes(0)
		// 	errChan <- nil
		// 	err = testclienthelper(eventInfo)
		//
		// 	So(err, ShouldBeNil)
		// 	testRPCMonitor.Stop()
		// })

		Convey("AddProcessFails", func() {
			clist := make(chan string, 1)
			clist <- ""

			contextstore.EXPECT().WalkStore().Return(clist, nil)

			testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil, puHandler, &collector.DefaultCollector{}, netcls, contextstore)
			err := testRPCMonitor.Start()
			if err != nil {
				fmt.Println(err)
				t.SkipNow()
			}
			markmap := make(map[string]string)
			markmap["@cgroup_mark"] = "100"
			var mark uint64 = 100
			eventInfo := &EventInfo{
				EventType: monitor.EventStart,
				PUID:      "/test1", //This will cause the failure
				Name:      "testservice",
				Tags:      markmap,
				PID:       "12345",
				IPs:       nil,
			}
			tags := &policy.TagsMap{Tags: make(map[string]string)}
			tags.Add("@cgroup_mark", "100")
			runtime := policy.NewPURuntime(eventInfo.Name, 12345, tags, nil, policy.ContainerPU, nil)
			puHandler.EXPECT().SetPURuntime("/test1", runtime)
			errChan := make(chan error, 1)
			puHandler.EXPECT().HandlePUEvent("/test1", monitor.EventStart).Return(errChan)
			netcls.EXPECT().Creategroup(eventInfo.PUID).MaxTimes(1).Return(nil)
			netcls.EXPECT().AssignMark(eventInfo.PUID, mark).MaxTimes(1).Return(nil)
			netcls.EXPECT().AddProcess(eventInfo.PUID, 12345).MaxTimes(1).Return(errors.New("Add Process error"))
			netcls.EXPECT().DeleteCgroup(eventInfo.PUID).MaxTimes(1)
			errChan <- nil

			err = testclienthelper(eventInfo)

			So(err, ShouldNotBeNil)
			testRPCMonitor.Stop()
		})

	})
}

func TestHandleStopEvent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	netcls := mock_cgnetcls.NewMockCgroupnetcls(ctrl)
	contextstore := mock_contextstore.NewMockContextStore(ctrl)
	puHandler := mock_trireme.NewMockProcessingUnitsHandler(ctrl)
	Convey("Testing handlstopevent", t, func() {
		Convey("We pass invalid contextID  eventInfo we return error", func() {
			clist := make(chan string, 1)
			clist <- ""

			contextstore.EXPECT().WalkStore().Return(clist, nil)

			testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil, puHandler, nil, netcls, contextstore)
			err := testRPCMonitor.Start()
			if err != nil {
				fmt.Println(err)
				t.SkipNow()
			}

			eventInfo := &EventInfo{
				EventType: monitor.EventStop,
				PUID:      "", //This will cause the failure
				Name:      "testservice",
				Tags:      nil,
				PID:       "12345",
				IPs:       nil,
			}

			err = testclienthelper(eventInfo)
			So(err, ShouldNotBeNil)
			testRPCMonitor.Stop()
		})

		// Convey("DeleteBasePath Returns true: We are deleting our base directory ", func() {
		// 	clist := make(chan string, 1)
		// 	clist <- ""
		//
		// 	contextstore.EXPECT().WalkStore().Return(clist, nil)
		//
		// 	testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil, puHandler, nil, netcls, contextstore)
		// 	err := testRPCMonitor.Start()
		// 	if err != nil {
		// 		fmt.Println(err)
		// 		t.SkipNow()
		// 	}
		//
		// 	eventInfo := &EventInfo{
		// 		EventType: monitor.EventStop,
		// 		PUID:      "/aporeto", //This will cause the failure
		// 		Name:      "testservice",
		// 		Tags:      nil,
		// 		PID:       "12345",
		// 		IPs:       nil,
		// 	}
		// 	netcls.EXPECT().Deletebasepath(eventInfo.PUID).Return(true)
		// 	puHandler.EXPECT().HandlePUEvent(eventInfo.PUID, monitor.EventStop).MaxTimes(0)
		// 	err = testclienthelper(eventInfo)
		// 	So(err, ShouldBeNil)
		// 	testRPCMonitor.Stop()
		//
		// })

		// Convey("HandlePUEvent returns error:Stop event failed ", func() {
		// 	clist := make(chan string, 1)
		// 	clist <- ""
		//
		// 	contextstore.EXPECT().WalkStore().Return(clist, nil)
		//
		// 	testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil, puHandler, nil, netcls, contextstore)
		// 	err := testRPCMonitor.Start()
		// 	if err != nil {
		// 		fmt.Println(err)
		// 		t.SkipNow()
		// 	}
		//
		// 	eventInfo := &EventInfo{
		// 		EventType: monitor.EventStop,
		// 		PUID:      "/aporeto", //This will cause the failure
		// 		Name:      "testservice",
		// 		Tags:      nil,
		// 		PID:       "12345",
		// 		IPs:       nil,
		// 	}
		// 	netcls.EXPECT().Deletebasepath(eventInfo.PUID).Return(false)
		// 	errChan := make(chan error, 1)
		// 	puHandler.EXPECT().HandlePUEvent(eventInfo.PUID, monitor.EventStop).MaxTimes(1).Return(errChan)
		// 	netcls.EXPECT().DeleteCgroup(eventInfo.PUID).MaxTimes(1)
		// 	contextstore.EXPECT().RemoveContext(eventInfo.PUID).MaxTimes(1)
		// 	errChan <- errors.New("PUEVENT STOP error")
		// 	err = testclienthelper(eventInfo)
		// 	So(err, ShouldNotBeNil)
		// 	testRPCMonitor.Stop()
		//
		// })

		// Convey("handlestopevent processed sucessfully ", func() {
		// 	clist := make(chan string, 1)
		// 	clist <- ""
		//
		// 	contextstore.EXPECT().WalkStore().Return(clist, nil)
		//
		// 	testRPCMonitor, _ := NewRPCMonitor(testRPCAddress, nil, puHandler, nil, netcls, contextstore)
		// 	err := testRPCMonitor.Start()
		// 	if err != nil {
		// 		fmt.Println(err)
		// 		t.SkipNow()
		// 	}
		//
		// 	eventInfo := &EventInfo{
		// 		EventType: monitor.EventStop,
		// 		PUID:      "/aporeto", //This will cause the failure
		// 		Name:      "testservice",
		// 		Tags:      nil,
		// 		PID:       "12345",
		// 		IPs:       nil,
		// 	}
		// 	netcls.EXPECT().Deletebasepath(eventInfo.PUID).Return(false)
		// 	errChan := make(chan error, 1)
		// 	puHandler.EXPECT().HandlePUEvent(eventInfo.PUID, monitor.EventStop).MaxTimes(1).Return(errChan)
		// 	netcls.EXPECT().DeleteCgroup(eventInfo.PUID).MaxTimes(0)
		// 	contextstore.EXPECT().RemoveContext(eventInfo.PUID).MaxTimes(0)
		// 	errChan <- nil
		// 	err = testclienthelper(eventInfo)
		// 	So(err, ShouldBeNil)
		// 	testRPCMonitor.Stop()
		//
		// })
	})
}
