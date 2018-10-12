package policy

import (
	"testing"

	"github.com/docker/go-connections/nat"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/common"
)

func TestNewPURunTime(t *testing.T) {
	Convey("When I create a new run time, it should be valid", t, func() {

		tags := NewTagStore()
		tags.AppendKeyValue("image", "nginx")
		tags.AppendKeyValue("server", "local")

		ips := ExtendedMap{DefaultNamespace: "172.0.0.1"}

		runtime := NewPURuntime(
			"container1",
			123,
			"",
			tags,
			ips,
			common.ContainerPU,
			nil,
		)

		So(runtime, ShouldNotBeNil)
		So(runtime.puType, ShouldEqual, common.ContainerPU)
		So(runtime.tags, ShouldResemble, tags)
		So(runtime.ips, ShouldResemble, ips)
		So(runtime.options, ShouldNotBeNil)
		So(runtime.pid, ShouldEqual, 123)
		So(runtime.name, ShouldResemble, "container1")
	})
}

func TestNewPDefaultURunTime(t *testing.T) {
	Convey("When I create a new run time, it should be valid", t, func() {
		runtime := NewPURuntimeWithDefaults()

		So(runtime, ShouldNotBeNil)
		So(runtime.puType, ShouldEqual, common.ContainerPU)
		So(runtime.tags, ShouldResemble, NewTagStore())
		So(runtime.ips, ShouldResemble, ExtendedMap{})
		So(runtime.options, ShouldNotBeNil)
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

		portMap := map[nat.Port][]string{nat.Port("80"): {"8001", "8002"}}

		runtime := NewPURuntime(
			"container1",
			123,
			"",
			tags,
			ips,
			common.ContainerPU,
			nil,
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
			runtime.SetPUType(common.LinuxProcessPU)
			So(runtime.PUType(), ShouldEqual, common.LinuxProcessPU)
		})

		Convey("I should be able to set and get the right options", func() {
			runtime.SetOptions(OptionsType{CgroupName: "test"})
			So(runtime.Options(), ShouldResemble, OptionsType{CgroupName: "test"})
		})

		Convey("I should be able to set portmap in options and get the right portmap", func() {
			runtime.SetOptions(OptionsType{PortMap: portMap})
			So(runtime.PortMap(), ShouldResemble, portMap)
		})

		Convey("I should ge the right name", func() {
			So(runtime.Name(), ShouldEqual, "container1")
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

		Convey("I should be able to set the tags", func() {
			modify := &TagStore{Tags: []string{"$set=new"}}
			runtime.SetTags(modify)
			So(runtime.Tags(), ShouldResemble, modify)
			value, ok := runtime.Tag("$set")
			So(ok, ShouldBeTrue)
			So(value, ShouldEqual, "new")
			_, ok = runtime.Tag("image")
			So(ok, ShouldBeFalse)
		})
	})
}
