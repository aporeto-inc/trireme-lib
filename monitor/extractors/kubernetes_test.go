package extractors

import (
	"reflect"
	"testing"

	"go.aporeto.io/trireme-lib/policy"
	api "k8s.io/api/core/v1"
)

func TestDefaultKubernetesMetadataExtractor(t *testing.T) {

	pod1 := &api.Pod{}
	pod1.SetName("test")
	pod1.SetNamespace("ns")
	pod1.SetLabels(map[string]string{
		"label": "one",
	})

	runtimeDocker := policy.NewPURuntimeWithDefaults()
	tags := runtimeDocker.Tags()
	tags.AppendKeyValue(KubernetesContainerNameIdentifier, "POD")
	runtimeDocker.SetTags(tags)

	runtimeResult := policy.NewPURuntimeWithDefaults()
	tags = runtimeResult.Tags()
	tags.AppendKeyValue("label", "one")
	tags.AppendKeyValue(UpstreamOldNameIdentifier, "test")
	tags.AppendKeyValue(UpstreamNameIdentifier, "test")
	tags.AppendKeyValue(UpstreamOldNamespaceIdentifier, "ns")
	tags.AppendKeyValue(UpstreamNamespaceIdentifier, "ns")

	runtimeResult.SetTags(tags)

	type args struct {
		runtime policy.RuntimeReader
		pod     *api.Pod
	}
	tests := []struct {
		name    string
		args    args
		want    *policy.PURuntime
		want1   bool
		wantErr bool
	}{
		{
			name: "empty1",
			args: args{
				runtime: nil,
				pod:     &api.Pod{},
			},
			wantErr: true,
		},
		{
			name: "empty2",
			args: args{
				runtime: policy.NewPURuntimeWithDefaults(),
				pod:     nil,
			},
			wantErr: true,
		},
		{
			name: "Simple test, non Kubernetes Container",
			args: args{
				runtime: policy.NewPURuntimeWithDefaults(),
				pod:     pod1,
			},
			want:    nil,
			want1:   false,
			wantErr: false,
		},
		{
			name: "Simple test",
			args: args{
				runtime: runtimeDocker,
				pod:     pod1,
			},
			want:    runtimeResult,
			want1:   true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := DefaultKubernetesMetadataExtractor(tt.args.runtime, tt.args.pod)
			if (err != nil) != tt.wantErr {
				t.Errorf("DefaultKubernetesMetadataExtractor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DefaultKubernetesMetadataExtractor() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("DefaultKubernetesMetadataExtractor() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
