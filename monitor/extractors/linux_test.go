// +build linux

package extractors

import (
	"encoding/hex"
	"net"
	"reflect"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/policy"
	portspec "go.aporeto.io/trireme-lib/utils/portspec"
)

func TestComputeFileMd5(t *testing.T) {

	Convey("When I calculate the MD5 of a bad file", t, func() {
		_, err := computeFileMd5("testdata/nofile")
		Convey("I should get an error", func() {
			So(err, ShouldNotBeNil)
		})
	})

	Convey("When I calculate the MD5 of a good file", t, func() {
		hash, err := computeFileMd5("testdata/curl")
		Convey("I should get no error and the right value", func() {
			So(err, ShouldBeNil)
			So(hex.EncodeToString(hash), ShouldResemble, "bf7e66d7bbd0465cfcba5b1cf68a9b59")
		})
	})
}

func TestFindFQDN(t *testing.T) {

	Convey("When I try to get the hostname of a good host", t, func() {
		hostname := findFQDN(1000 * time.Second)

		Convey("I should be able to resolve this hostname", func() {
			addr, err := net.LookupHost(hostname)
			So(err, ShouldBeNil)
			So(len(addr), ShouldBeGreaterThan, 0)
		})
	})
}

func TestLibs(t *testing.T) {

	Convey("When I try to get the libraries of a known binary", t, func() {
		libraries := libs("./testdata/curl")
		Convey("I should get the execpted libraries", func() {
			So(len(libraries), ShouldEqual, 4)
			So(libraries, ShouldContain, "libcurl-gnutls.so.4")
			So(libraries, ShouldContain, "libz.so.1")
			So(libraries, ShouldContain, "libpthread.so.0")
			So(libraries, ShouldContain, "libc.so.6")
		})
	})

	Convey("When I try to get the libraries of a bad binary", t, func() {

		libraries := libs("./testdata/nofile")
		Convey("I should get an empty array", func() {
			So(len(libraries), ShouldEqual, 0)
		})
	})
}

func TestSystemdEventMetadataExtractor(t *testing.T) {

	Convey("When I call the metadata extrator", t, func() {

		Convey("If all data are present", func() {
			event := &common.EventInfo{
				Name:       "./testdata/curl",
				Executable: "./testdata/curl",
				PID:        1234,
				PUID:       "/1234",
				Tags:       []string{"app=web"},
			}

			pu, err := SystemdEventMetadataExtractor(event)
			Convey("I should get no error and a valid PU runitime", func() {
				So(err, ShouldBeNil)
				So(pu, ShouldNotBeNil)
			})
		})
	})
}

func TestDefaultHostMetadataExtractor(t *testing.T) {

	Convey("When I call the host metadata extractor", t, func() {

		Convey("If its valid data", func() {

			s, _ := portspec.NewPortSpecFromString("1000", nil) // nolint
			services := []common.Service{
				{
					Protocol: uint8(6),
					Ports:    s,
				},
			}

			event := &common.EventInfo{
				Name:     "Web",
				PID:      1234,
				PUID:     "Web",
				Tags:     []string{"app=web"},
				Services: services,
			}

			pu, err := DefaultHostMetadataExtractor(event)
			Convey("I should get no error and a valid PU runtimg", func() {
				So(err, ShouldBeNil)
				So(pu, ShouldNotBeNil)
				So(pu.Options().CgroupName, ShouldResemble, "Web")
				So(pu.Options().Services, ShouldResemble, services)
			})
		})

		Convey("If I get invalid tags", func() {

			event := &common.EventInfo{
				Name: "Web",
				PID:  1234,
				PUID: "Web",
				Tags: []string{"invalid"},
			}

			_, err := DefaultHostMetadataExtractor(event)
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If I get an invalid PID", func() {

			event := &common.EventInfo{
				Name: "Web",
				PID:  -1233,
				PUID: "Web",
				Tags: []string{"invalid"},
			}

			_, err := DefaultHostMetadataExtractor(event)
			Convey("I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func Test_policyExtensions(t *testing.T) {
	type args struct {
		runtime policy.RuntimeReader
	}

	pur1 := policy.NewPURuntime("", 0, "", nil, nil, common.LinuxProcessPU, nil)
	em1 := policy.ExtendedMap{
		"Key": "Value",
	}
	options := pur1.Options()
	options.PolicyExtensions = em1
	pur1.SetOptions(options)

	// 2nd Runtime
	pur2 := policy.NewPURuntime("", 0, "", nil, nil, common.LinuxProcessPU, nil)
	options = pur2.Options()
	pur2.SetOptions(options)

	// 3rd runtime
	pur3 := policy.NewPURuntime("", 0, "", nil, nil, common.LinuxProcessPU, nil)
	options = pur3.Options()
	options.PolicyExtensions = nil
	pur3.SetOptions(options)

	tests := []struct {
		name           string
		args           args
		wantExtensions policy.ExtendedMap
	}{
		// TODO: Add test cases.
		{
			name: "Test if runtime is nil",
			args: args{
				runtime: nil,
			},
			wantExtensions: nil,
		},
		{
			name: "Test if policy extensions are nil",
			args: args{
				runtime: pur3,
			},
			wantExtensions: nil,
		},
		{
			name: "Test if policy extensions are defined",
			args: args{
				runtime: pur1,
			},
			wantExtensions: em1,
		},
		{
			name: "Test if policy extensions are not defined",
			args: args{
				runtime: pur2,
			},
			wantExtensions: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotExtensions := policyExtensions(tt.args.runtime); !reflect.DeepEqual(gotExtensions, tt.wantExtensions) {
				t.Errorf("policyExtensions() = %v, want %v", gotExtensions, tt.wantExtensions)
			}
		})
	}
}

func TestIsHostmodePU(t *testing.T) {
	type args struct {
		runtime policy.RuntimeReader
		mode    constants.ModeType
	}

	pur1 := policy.NewPURuntime("", 0, "", nil, nil, common.HostPU, nil)

	// 2nd Runtime
	pur2 := policy.NewPURuntime("", 0, "", nil, nil, common.HostNetworkPU, nil)

	// 3rd runtime
	pur3 := policy.NewPURuntime("", 0, "", nil, nil, common.LinuxProcessPU, nil)

	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Test if pu type is Container",
			args: args{
				runtime: nil,
				mode:    constants.RemoteContainer,
			},
			want: false,
		},
		{
			name: "Test if PU type is hostpu",
			args: args{
				runtime: pur1,
				mode:    constants.LocalServer,
			},
			want: true,
		},
		{
			name: "Test if pu type is hostnetworkmode pu",
			args: args{
				runtime: pur2,
				mode:    constants.LocalServer,
			},
			want: true,
		},
		{
			name: "Test if pu type is linux pu",
			args: args{
				runtime: pur3,
				mode:    constants.LocalServer,
			},
			want: false,
		},
		{
			name: "Test invalid runtime",
			args: args{
				runtime: nil,
				mode:    constants.LocalServer,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsHostmodePU(tt.args.runtime, tt.args.mode); got != tt.want {
				t.Errorf("IsHostmodePU() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsHostPU(t *testing.T) {
	type args struct {
		runtime policy.RuntimeReader
		mode    constants.ModeType
	}

	pur1 := policy.NewPURuntime("", 0, "", nil, nil, common.HostPU, nil)

	// 2nd Runtime
	pur2 := policy.NewPURuntime("", 0, "", nil, nil, common.HostNetworkPU, nil)

	// 3rd runtime
	pur3 := policy.NewPURuntime("", 0, "", nil, nil, common.LinuxProcessPU, nil)

	tests := []struct {
		name string
		args args
		want bool
	}{{
		name: "Test if pu type is Container",
		args: args{
			runtime: nil,
			mode:    constants.RemoteContainer,
		},
		want: false,
	},
		{
			name: "Test if PU type is hostpu",
			args: args{
				runtime: pur1,
				mode:    constants.LocalServer,
			},
			want: true,
		},
		{
			name: "Test if pu type is hostnetworkmode pu",
			args: args{
				runtime: pur2,
				mode:    constants.LocalServer,
			},
			want: false,
		},
		{
			name: "Test if pu type is linux pu",
			args: args{
				runtime: pur3,
				mode:    constants.LocalServer,
			},
			want: false,
		},
		{
			name: "Test invalid runtime",
			args: args{
				runtime: nil,
				mode:    constants.LocalServer,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsHostPU(tt.args.runtime, tt.args.mode); got != tt.want {
				t.Errorf("IsHostPU() = %v, want %v", got, tt.want)
			}
		})
	}
}
