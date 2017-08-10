package policy

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/aporeto-inc/trireme/constants"
)

func TestNewPURunTime(t *testing.T) {
	Convey("When I create a new run time, it should be valid", t, func() {

		tags := NewTagStore()
		tags.AppendKeyValue("image", "nginx")
		tags.AppendKeyValue("server", "local")

		ips := ExtendedMap{DefaultNamespace: "172.0.0.1"}
		options := ExtendedMap{
			"Activate": "true",
		}

		runtime := NewPURuntime(
			"container1",
			123,
			"",
			tags,
			ips,
			constants.ContainerPU,
			options,
		)

		So(runtime, ShouldNotBeNil)
		So(runtime.puType, ShouldEqual, constants.ContainerPU)
		So(runtime.tags, ShouldResemble, tags)
		So(runtime.ips, ShouldResemble, ips)
		So(runtime.options, ShouldResemble, options)
		So(runtime.pid, ShouldEqual, 123)
		So(runtime.name, ShouldResemble, "container1")
	})
}

func TestNewPDefaultURunTime(t *testing.T) {
	Convey("When I create a new run time, it should be valid", t, func() {
		runtime := NewPURuntimeWithDefaults()

		So(runtime, ShouldNotBeNil)
		So(runtime.puType, ShouldEqual, constants.ContainerPU)
		So(runtime.tags, ShouldResemble, NewTagStore())
		So(runtime.ips, ShouldResemble, ExtendedMap{})
		So(runtime.options, ShouldResemble, ExtendedMap{})
		So(runtime.pid, ShouldEqual, 0)
		So(runtime.name, ShouldResemble, "")
	})
}

func TestBasicFunctions(t *testing.T) {
	Convey("Given a valid runtime", t, func() {
		tags := NewTagStore()
		tags.AppendKeyValue("image", "nginx")
		tags.AppendKeyValue("server", "local")

		ips := ExtendedMap{DefaultNamespace: "172.0.0.1"}
		options := ExtendedMap{
			"Activate": "true",
		}

		runtime := NewPURuntime(
			"container1",
			123,
			"",
			tags,
			ips,
			constants.ContainerPU,
			options,
		)

		Convey("When I clone it, I should get the right runtime", func() {
			cloned := runtime.Clone()
			So(cloned, ShouldResemble, runtime)
		})

		Convey("I should retrieve the right Pid", func() {
			So(runtime.Pid(), ShouldEqual, 123)
		})

		Convey("I shopuld be able to set the Pid", func() {
			runtime.SetPid(567)
			So(runtime.Pid(), ShouldEqual, 567)
		})

		Convey("I should be able to update and get the PUType", func() {
			runtime.SetPUType(constants.LinuxProcessPU)
			So(runtime.PUType(), ShouldEqual, constants.LinuxProcessPU)
		})

		Convey("I should be able to set and ge the right options", func() {
			runtime.SetOptions(ExtendedMap{
				"newoptions": "newvalues",
			})
			So(runtime.Options(), ShouldResemble, ExtendedMap{
				"newoptions": "newvalues",
			})
		})

		Convey("I should ge the right name", func() {
			So(runtime.Name(), ShouldEqual, "container1")
		})

		Convey("I should get the right IP addresses", func() {
			So(runtime.IPAddresses(), ShouldResemble, ips)
			defaultIP, ok := runtime.DefaultIPAddress()
			So(ok, ShouldBeTrue)
			So(defaultIP, ShouldResemble, "172.0.0.1")
		})

		Convey("If I update the IP addresses, they should updated", func() {
			runtime.SetIPAddresses(ExtendedMap{DefaultNamespace: "10.1.1.1"})
			So(runtime.IPAddresses(), ShouldResemble, ExtendedMap{DefaultNamespace: "10.1.1.1"})
		})

		Convey("I should be able to get the tags", func() {
			So(runtime.Tags(), ShouldResemble, tags)
			value, ok := runtime.Tag("image")
			So(ok, ShouldBeTrue)
			So(value, ShouldEqual, "nginx")
		})
	})
}
