package dockermonitor

import (
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/docker/docker/api/types"
	. "github.com/smartystreets/goconvey/convey"
)

var testDockerMetadataExtractor DockerMetadataExtractor

func eventCollector() collector.EventCollector {
	newEvent := &collector.DefaultCollector{}
	return newEvent
}

func initTestDockerInfo() *types.ContainerJSON {
	var testInfo types.ContainerJSON
	var m map[string]string
	m = make(map[string]string)
	m["role"] = "client"
	m["vendor"] = "CentOS"
	m["$id"] = "598a35a60f79af0001b52ef5"
	m["$namespace"] = "/sibicentos"
	m["build-date"] = "20170801"
	m["license"] = "GPLv2"
	m["name"] = "CentOS Base Image"

	testInfo.Config.Image = "centos"
	testInfo.Name = "/priceless_rosalind"
	testInfo.Config.Labels = m
	testInfo.NetworkSettings.IPAddress = "172.17.0.2"
	testInfo.State.Pid = 4912
	testInfo.HostConfig.NetworkMode = "default"

	return &testInfo
}

func TestNewDockerMonitor(t *testing.T) {
	Convey("When I try to initialize a new docker monitor", t, func() {
		dm := NewDockerMonitor(constants.DefaultDockerSocketType, constants.DefaultDockerSocket, nil, testDockerMetadataExtractor, eventCollector(), false, nil, false)

		Convey("Then docker monitor should not be nil", func() {
			So(dm, ShouldNotBeNil)
		})
	})
}

func TestInitDockerClient(t *testing.T) {
	Convey("When I try to initialize a new docker client as unix", t, func() {
		dc, err := initDockerClient(constants.DefaultDockerSocketType, constants.DefaultDockerSocket)

		Convey("Then docker client should not be nil", func() {
			So(dc, ShouldNotBeNil)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I try to initialize a new docker client as tcp", t, func() {
		dc, err := initDockerClient("tcp", constants.DefaultDockerSocket)

		Convey("Then docker client should not be nil", func() {
			So(dc, ShouldNotBeNil)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I try to initialize a new docker client with some random type", t, func() {
		dc, err := initDockerClient("wrongType", constants.DefaultDockerSocket)

		Convey("Then docker client should be nil and I should get error", func() {
			So(dc, ShouldBeNil)
			So(err, ShouldResemble, fmt.Errorf("Bad socket type wrongType"))
		})
	})

	Convey("When I try to initialize a new docker client with some random path", t, func() {
		dc, err := initDockerClient(constants.DefaultDockerSocketType, "/var/random.sock")

		Convey("Then docker client should be nil and I should get error", func() {
			So(dc, ShouldBeNil)
			So(err, ShouldResemble, &os.PathError{Op: "stat", Path: "/var/random.sock", Err: syscall.Errno(2)})
		})
	})
}

func TestContextIDFromDockerID(t *testing.T) {
	Convey("When I try to retrieve contextID from dockerID", t, func() {
		cID, err := contextIDFromDockerID("b06f47830f64")
		cID1 := "b06f47830f64"

		Convey("Then contextID should match", func() {
			So(cID, ShouldEqual, cID1)
			So(err, ShouldBeNil)
		})
	})

	Convey("When I try to retrieve contextID when dockerID length less than 12", t, func() {
		cID, err := contextIDFromDockerID("6f47830f64")

		Convey("Then I should get error", func() {
			So(cID, ShouldEqual, "")
			So(err, ShouldResemble, fmt.Errorf("dockerID smaller than 12 characters"))
		})
	})

	Convey("When I try to retrieve contextID when no dockerID given", t, func() {
		cID, err := contextIDFromDockerID("")

		Convey("Then I should get error", func() {
			So(cID, ShouldEqual, "")
			So(err, ShouldResemble, fmt.Errorf("Empty DockerID String"))
		})
	})
}

func TestDefaultDockerMetadataExtractor(t *testing.T) {
	Convey("When I try to extract metadata from docker container", t, func() {
		puR, err := defaultDockerMetadataExtractor(initTestDockerInfo())

		Convey("Then I should not get any error", func() {
			So(puR, ShouldNotBeNil)
			So(err, ShouldBeNil)
		})
	})
}
