// +build linux

package dockermonitor

import (
	"reflect"
	"testing"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/constants"
	"go.aporeto.io/trireme-lib/policy"
)

func TestGetPausePUID(t *testing.T) {
	type args struct {
		extensions policy.ExtendedMap
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test when puid is populated",
			args: args{
				extensions: policy.ExtendedMap{
					constants.DockerHostPUID: "1234",
				},
			},
			want: "1234",
		},
		{
			name: "Test when puid is not populated",
			args: args{
				extensions: policy.ExtendedMap{},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getPausePUID(tt.args.extensions); got != tt.want {
				t.Errorf("GetPausePUID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyExtensions(t *testing.T) {

	puRuntimeWithExtensions := func() *policy.PURuntime {
		extensions := policy.ExtendedMap{}
		extensions[constants.DockerHostPUID] = "1234"
		puRuntime := policy.NewPURuntimeWithDefaults()
		options := puRuntime.Options()
		options.PolicyExtensions = extensions
		puRuntime.SetOptions(options)
		return puRuntime
	}

	puRuntimeWithWrongExtensions := func() *policy.PURuntime {
		puRuntime := policy.NewPURuntimeWithDefaults()
		extensions := "abcd"
		options := puRuntime.Options()
		options.PolicyExtensions = extensions
		puRuntime.SetOptions(options)
		return puRuntime
	}

	type args struct {
		runtime policy.RuntimeReader
	}
	tests := []struct {
		name           string
		args           args
		wantExtensions policy.ExtendedMap
	}{
		{
			name: "Valid case with extensions defined",
			args: args{
				runtime: puRuntimeWithExtensions(),
			},
			wantExtensions: policy.ExtendedMap{
				constants.DockerHostPUID: "1234",
			},
		},
		{
			name: "Runtime with no extensions defined",
			args: args{
				runtime: policy.NewPURuntimeWithDefaults(),
			},
			wantExtensions: nil,
		},
		{
			name: "Nil runntime",
			args: args{
				runtime: nil,
			},
			wantExtensions: nil,
		},
		{
			name: "extensions which isnt a map",
			args: args{
				runtime: puRuntimeWithWrongExtensions(),
			},
			wantExtensions: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotExtensions := policyExtensions(tt.args.runtime); !reflect.DeepEqual(gotExtensions, tt.wantExtensions) {
				t.Errorf("PolicyExtensions() = %v, want %v", gotExtensions, tt.wantExtensions)
			}
		})
	}
}

func TestIsKubernetesContainer(t *testing.T) {

	type args struct {
		labels map[string]string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Test if container is in kubernetes",
			args: args{
				labels: map[string]string{
					constants.K8sPodNamespace: "abcd",
					constants.K8sPodName:      "abcd",
				},
			},
			want: true,
		},
		{
			name: "Test if container is not in kubernetes",
			args: args{
				labels: map[string]string{
					"app": "nginx",
				},
			},
			want: false,
		},
		{
			name: "Test for empty labels",
			args: args{
				labels: nil,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isKubernetesContainer(tt.args.labels); got != tt.want {
				t.Errorf("IsKubernetesContainer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isHostNetworkContainer(t *testing.T) {

	puRuntimeWithExtensions := func() *policy.PURuntime {
		extensions := policy.ExtendedMap{
			constants.DockerHostPUID: "1234",
		}
		puRuntime := policy.NewPURuntimeWithDefaults()
		options := puRuntime.Options()
		options.PolicyExtensions = extensions
		puRuntime.SetOptions(options)
		return puRuntime
	}

	puRuntimeForProcess := func() *policy.PURuntime {
		puRuntime := policy.NewPURuntimeWithDefaults()
		puRuntime.SetPUType(common.LinuxProcessPU)
		return puRuntime
	}

	type args struct {
		runtime policy.RuntimeReader
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Test when puid is populated",
			args: args{
				runtime: puRuntimeWithExtensions(),
			},
			want: true,
		},
		{
			name: "Test when puid is not populated",
			args: args{
				runtime: policy.NewPURuntimeWithDefaults(),
			},
			want: false,
		},
		{
			name: "Test when runtime is of Linux process pu",
			args: args{
				runtime: puRuntimeForProcess(),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHostNetworkContainer(tt.args.runtime); got != tt.want {
				t.Errorf("isHostNetworkContainer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_kubePodIdentifier(t *testing.T) {
	type args struct {
		labels map[string]string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test valid scenario",
			args: args{
				labels: map[string]string{
					constants.K8sPodNamespace: "abcd",
					constants.K8sPodName:      "abcd",
				},
			},
			want: "abcd/abcd",
		},
		{
			name: "Test when only one of tags are present",
			args: args{
				labels: map[string]string{
					constants.K8sPodNamespace: "abcd",
				},
			},
			want: "",
		},
		{
			name: "Test when only no k8s tags are present",
			args: args{
				labels: map[string]string{},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := kubePodIdentifier(tt.args.labels); got != tt.want {
				t.Errorf("kubePodIdentifier() = %v, want %v", got, tt.want)
			}
		})
	}
}
