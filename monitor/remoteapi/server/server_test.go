package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/processor/mockprocessor"
	"go.aporeto.io/trireme-lib/monitor/registerer"
)

func TestNewEventServer(t *testing.T) {
	Convey("When I create a new server", t, func() {
		reg := registerer.New()
		s, err := NewEventServer("/tmp/trireme.sock", reg)
		Convey("The object should be correct", func() {
			So(err, ShouldBeNil)
			So(s, ShouldNotBeNil)
			So(s.socketPath, ShouldResemble, "/tmp/trireme.sock")
			So(s.registerer, ShouldEqual, reg)
		})
	})
}

func TestValidateUser(t *testing.T) {
	Convey("When I try to validate a user", t, func() {

		Convey("When I get a bad remote address, it should fail", func() {
			r := &http.Request{}
			r.RemoteAddr = "badpath"
			event := &common.EventInfo{}

			err := validateUser(r, event)
			So(err, ShouldNotBeNil)
		})

		Convey("When I issue the request as a superuser it should always succeed", func() {
			r := &http.Request{}
			r.RemoteAddr = "0:0:1000"
			event := &common.EventInfo{}

			err := validateUser(r, event)
			So(err, ShouldBeNil)
		})

		Convey("When I issue the request as a regular user with a bad process it should fail", func() {
			r := &http.Request{}
			r.RemoteAddr = "1:10:1000"
			event := &common.EventInfo{PID: -1}

			err := validateUser(r, event)
			So(err, ShouldNotBeNil)
		})

		Convey("When I issue the request as a regular user to a foreign process", func() {

			myuid := strconv.Itoa(os.Getuid())
			myguyid := strconv.Itoa(os.Getgid())
			mypid := int32(os.Getpid())
			mypidstring := strconv.Itoa(int(mypid))

			r := &http.Request{}
			r.RemoteAddr = myuid + ":" + myguyid + ":" + mypidstring
			event := &common.EventInfo{PID: 0}

			err := validateUser(r, event)
			So(err, ShouldNotBeNil)
		})

		Convey("When I issue the request as a regular user with valid pid", func() {

			myuid := strconv.Itoa(os.Getuid())
			myguyid := strconv.Itoa(os.Getgid())
			mypid := int32(os.Getpid())
			mypidstring := strconv.Itoa(int(mypid))

			r := &http.Request{}
			r.RemoteAddr = myuid + ":" + myguyid + ":" + mypidstring
			event := &common.EventInfo{PID: mypid}

			err := validateUser(r, event)
			So(err, ShouldBeNil)
		})

	})
}

func TestValidateTypes(t *testing.T) {
	Convey("When I validate the types of an event", t, func() {

		Convey("If I have a bad eventtype it should error.", func() {
			event := &common.EventInfo{
				EventType: common.Event(123),
			}

			err := validateTypes(event)
			So(err, ShouldNotBeNil)
		})

		Convey("If I have a bad PUType it should error.", func() {
			event := &common.EventInfo{
				EventType: common.EventStart,
				PUType:    common.PUType(123),
			}

			err := validateTypes(event)
			So(err, ShouldNotBeNil)
		})

		Convey("If the event name has utf8 charaters and it is NOT UIDPAM PU, it should succeed.", func() {
			event := &common.EventInfo{
				EventType: common.EventStart,
				PUType:    common.ContainerPU,
				Name:      "utf8-_!@#%&\" (*)+.,/$!:;<>=?{}~",
			}

			err := validateTypes(event)
			So(err, ShouldBeNil)
		})

		Convey("If the event name has utf8 charaters and it is UIDPAM PU, it should error.", func() {
			event := &common.EventInfo{
				EventType: common.EventStart,
				PUType:    common.UIDLoginPU,
				Name:      "utf8-_!@#%&\" (*)+.,/$!:;<>=?{}~",
			}

			err := validateTypes(event)
			So(err, ShouldNotBeNil)
		})

		Convey("If the cgroup has bad charaters, it should error.", func() {
			event := &common.EventInfo{
				EventType: common.EventStart,
				PUType:    common.ContainerPU,
				Name:      "Container",
				Cgroup:    "/potatoes",
			}

			err := validateTypes(event)
			So(err, ShouldNotBeNil)
		})

		Convey("If the namespace path has bad charaters, it should error.", func() {
			event := &common.EventInfo{
				EventType: common.EventStart,
				PUType:    common.ContainerPU,
				Name:      "Container",
				Cgroup:    "/trireme/123",
				NS:        "!@##$!#",
			}

			err := validateTypes(event)
			So(err, ShouldNotBeNil)
		})

		Convey("If the IPs have a bad name, it should error.", func() {
			event := &common.EventInfo{
				EventType: common.EventStart,
				PUType:    common.ContainerPU,
				Name:      "Container",
				Cgroup:    "/trireme/123",
				NS:        "/var/run/docker/netns/6f7287cc342b",
				IPs:       map[string]string{"^^^": "123"},
			}

			err := validateTypes(event)
			So(err, ShouldNotBeNil)
		})

		Convey("If the IP address is bad, it should error.", func() {
			event := &common.EventInfo{
				EventType: common.EventStart,
				PUType:    common.ContainerPU,
				Name:      "Container",
				Cgroup:    "/trireme/123",
				NS:        "/var/run/docker/netns/6f7287cc342b",
				IPs:       map[string]string{"bridge": "123"},
			}

			err := validateTypes(event)
			So(err, ShouldNotBeNil)
		})

		Convey("If all the types are correct, it should succeed.", func() {
			event := &common.EventInfo{
				EventType: common.EventStart,
				PUType:    common.ContainerPU,
				Name:      "Container",
				Cgroup:    "/trireme/123",
				NS:        "/var/run/docker/netns/6f7287cc342b",
				IPs:       map[string]string{"bridge": "172.17.0.1"},
			}

			err := validateTypes(event)
			So(err, ShouldBeNil)
		})

	})
}

func TestValidateEvent(t *testing.T) {
	Convey("When I validate events", t, func() {

		Convey("If I get a Create  with no HostService, and PUID is nil, I should update it.", func() {
			event := &common.EventInfo{
				EventType:   common.EventCreate,
				PID:         1,
				HostService: false,
			}

			err := validateEvent(event)
			So(err, ShouldBeNil)
			So(event.PUID, ShouldResemble, "1")
		})

		Convey("If I get a Create  with no HostService, and PUID is not nil, I should get the right PUID", func() {
			event := &common.EventInfo{
				EventType:   common.EventCreate,
				PID:         1,
				HostService: false,
				PUID:        "mypu",
			}

			err := validateEvent(event)
			So(err, ShouldBeNil)
			So(event.PUID, ShouldResemble, "mypu")
		})

		Convey("If I get a Create  with the HostService and no networktraffic only, I should get PUID with the same name", func() {
			event := &common.EventInfo{
				EventType:          common.EventCreate,
				PID:                1,
				HostService:        true,
				NetworkOnlyTraffic: false,
				PUID:               "mypu",
			}

			err := validateEvent(event)
			So(err, ShouldBeNil)
			So(event.PUID, ShouldResemble, "mypu")
		})

		Convey("If I get a Create  with the HostService and networktraffic only, I should get PUID as my name", func() {
			event := &common.EventInfo{
				EventType:          common.EventCreate,
				PID:                1,
				HostService:        true,
				NetworkOnlyTraffic: true,
				Name:               "myservice",
				PUID:               "mypu",
			}

			err := validateEvent(event)
			So(err, ShouldBeNil)
			So(event.PUID, ShouldResemble, "mypu")
		})

		Convey("If I get a Stop event and cgroup is in the right format, it should return nil.", func() {
			event := &common.EventInfo{
				EventType: common.EventStop,
				Cgroup:    "/trireme/1234",
			}

			err := validateEvent(event)
			So(err, ShouldBeNil)
		})

		Convey("If I get a Stop event and cgroup is in the wrong format, it should error.", func() {
			event := &common.EventInfo{
				EventType: common.EventStop,
				Cgroup:    "/potatoes",
			}

			err := validateEvent(event)
			So(err, ShouldNotBeNil)
		})

	})
}

func TestCreate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a new server", t, func() {
		reg := registerer.New()
		s, err := NewEventServer("/tmp/trireme.sock", reg)
		proc := mockprocessor.NewMockProcessor(ctrl)
		procerr := reg.RegisterProcessor(common.ContainerPU, proc)
		So(procerr, ShouldBeNil)

		So(err, ShouldBeNil)

		Convey("Given a valid event, I should get 200 response.", func() {
			event := &common.EventInfo{
				EventType: common.EventStart,
				PUType:    common.ContainerPU,
				PID:       int32(os.Getpid()),
				Name:      "Container",
				Cgroup:    "/trireme/123",
				NS:        "/var/run/docker/netns/6f7287cc342b",
				IPs:       map[string]string{"bridge": "172.17.0.1"},
			}

			proc.EXPECT().Start(gomock.Any(), gomock.Any()).Return(nil)

			b := new(bytes.Buffer)
			err := json.NewEncoder(b).Encode(event)
			So(err, ShouldBeNil)

			req := httptest.NewRequest("POST", "http://unix", b)
			req.RemoteAddr = strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()) + ":" + strconv.Itoa(int(event.PID))
			w := httptest.NewRecorder()
			s.create(w, req)

			So(w.Result().StatusCode, ShouldEqual, http.StatusAccepted)
		})

		Convey("Given bad json a BadRequest", func() {

			b := new(bytes.Buffer)
			b.WriteString("garbage")

			req := httptest.NewRequest("POST", "http://unix", b)

			w := httptest.NewRecorder()
			s.create(w, req)

			So(w.Result().StatusCode, ShouldEqual, http.StatusBadRequest)
		})

		Convey("Given bad event type, I should get BadRequest ", func() {
			event := &common.EventInfo{
				EventType: common.EventStart,
				PUType:    common.ContainerPU,
				PID:       -1,
				Name:      "^^^^",
				Cgroup:    "/trireme/123",
				NS:        "/var/run/docker/netns/6f7287cc342b",
				IPs:       map[string]string{"bridge": "172.17.0.1", "ip": "thisisnotip"},
			}

			b := new(bytes.Buffer)
			err := json.NewEncoder(b).Encode(event)
			So(err, ShouldBeNil)

			req := httptest.NewRequest("POST", "http://unix", b)
			// req.RemoteAddr = strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()) + ":" + strconv.Itoa(int(event.PID))
			w := httptest.NewRecorder()
			s.create(w, req)

			So(w.Result().StatusCode, ShouldEqual, http.StatusBadRequest)
		})

		Convey("Given a bad user request, I should get StatusForbidden ", func() {
			event := &common.EventInfo{
				EventType: common.EventStart,
				PUType:    common.ContainerPU,
				PID:       1,
				Name:      "name",
				Cgroup:    "/trireme/123",
				NS:        "/var/run/docker/netns/6f7287cc342b",
				IPs:       map[string]string{"bridge": "172.17.0.1"},
			}

			b := new(bytes.Buffer)
			err := json.NewEncoder(b).Encode(event)
			So(err, ShouldBeNil)

			req := httptest.NewRequest("POST", "http://unix", b)
			req.RemoteAddr = strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()) + ":" + strconv.Itoa(int(event.PID))
			w := httptest.NewRecorder()
			s.create(w, req)

			So(w.Result().StatusCode, ShouldEqual, http.StatusForbidden)
		})

		Convey("Given a bad event, I should get BadRequest ", func() {
			event := &common.EventInfo{
				EventType:          common.EventStart,
				PUType:             common.ContainerPU,
				PID:                int32(os.Getpid()),
				Name:               "",
				Cgroup:             "/trireme/123",
				NS:                 "/var/run/docker/netns/6f7287cc342b",
				IPs:                map[string]string{"bridge": "172.17.0.1"},
				HostService:        true,
				NetworkOnlyTraffic: true,
			}

			b := new(bytes.Buffer)
			err := json.NewEncoder(b).Encode(event)
			So(err, ShouldBeNil)

			req := httptest.NewRequest("POST", "http://unix", b)
			req.RemoteAddr = strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()) + ":" + strconv.Itoa(int(event.PID))
			w := httptest.NewRecorder()
			s.create(w, req)

			So(w.Result().StatusCode, ShouldEqual, http.StatusBadRequest)
		})

		Convey("Given a valid event,where the processor fails, I should get InternalServerError.", func() {
			event := &common.EventInfo{
				EventType: common.EventStart,
				PUType:    common.ContainerPU,
				PID:       int32(os.Getpid()),
				Name:      "Container",
				Cgroup:    "/trireme/123",
				NS:        "/var/run/docker/netns/6f7287cc342b",
				IPs:       map[string]string{"bridge": "172.17.0.1"},
			}

			proc.EXPECT().Start(gomock.Any(), gomock.Any()).Return(errors.New("some error"))

			b := new(bytes.Buffer)
			err := json.NewEncoder(b).Encode(event)
			So(err, ShouldBeNil)

			req := httptest.NewRequest("POST", "http://unix", b)
			req.RemoteAddr = strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()) + ":" + strconv.Itoa(int(event.PID))
			w := httptest.NewRecorder()
			s.create(w, req)

			So(w.Result().StatusCode, ShouldEqual, http.StatusInternalServerError)
		})

	})

}
