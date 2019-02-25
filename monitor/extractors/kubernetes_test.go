package extractors

import (
	"reflect"
	"testing"

	"go.aporeto.io/trireme-lib/policy"
	api "k8s.io/api/core/v1"
)

func TestDefaultKubernetesMetadataExtractor(t *testing.T) {
	t.SkipNow()
	pod1 := &api.Pod{}
	pod1.SetName("test")
	pod1.SetNamespace("ns")
	pod1.SetLabels(map[string]string{
		"label": "one",
	})

	runtimeResult := policy.NewPURuntimeWithDefaults()
	runtimeResult.SetIPAddresses(policy.ExtendedMap{"bridge": ""})
	tags := runtimeResult.Tags()
	tags.AppendKeyValue("label", "one")
	tags.AppendKeyValue(UpstreamNameIdentifier, "test")
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
				pod: &api.Pod{},
			},
			wantErr: true,
		},
		{
			name: "empty2",
			args: args{
				pod: nil,
			},
			wantErr: true,
		},
		{
			name: "Simple test",
			args: args{
				pod: pod1,
			},
			want:    runtimeResult,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DefaultKubernetesMetadataExtractor(tt.args.pod)
			if (err != nil) != tt.wantErr {
				t.Errorf("DefaultKubernetesMetadataExtractor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DefaultKubernetesMetadataExtractor() got = %v, want %v", got, tt.want)
			}
		})
	}
}
