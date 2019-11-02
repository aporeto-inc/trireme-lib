package extractors

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"go.aporeto.io/trireme-lib/v11/policy"
	api "k8s.io/api/core/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDefaultKubernetesMetadataExtractor(t *testing.T) {
	Convey("TestDefaultKubernetesMetadataExtractor", t, func() {
		pod1 := &corev1.Pod{}
		pod1.SetName("test")
		pod1.SetNamespace("ns")
		pod1.SetLabels(map[string]string{
			"    ":        "removeme",
			"label":       "one",
			"empty-label": "",
		})

		pod2 := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test2",
				Namespace: "ns",
			},
		}

		runtimeDocker := policy.NewPURuntimeWithDefaults()
		tags := runtimeDocker.Tags()
		tags.AppendKeyValue(KubernetesContainerNameIdentifier, "POD")
		runtimeDocker.SetTags(tags)

		runtimeResult1 := policy.NewPURuntimeWithDefaults()
		tags = runtimeResult1.Tags()
		tags.AppendKeyValue("label", "one")
		tags.AppendKeyValue("empty-label", "<empty>")
		tags.AppendKeyValue(UpstreamOldNameIdentifier, "test")
		tags.AppendKeyValue(UpstreamNameIdentifier, "test")
		tags.AppendKeyValue(UpstreamOldNamespaceIdentifier, "ns")
		tags.AppendKeyValue(UpstreamNamespaceIdentifier, "ns")
		runtimeResult1.SetTags(tags)

		runtimeResult2 := policy.NewPURuntimeWithDefaults()
		tags = runtimeResult2.Tags()
		tags.AppendKeyValue(UpstreamOldNameIdentifier, "test2")
		tags.AppendKeyValue(UpstreamNameIdentifier, "test2")
		tags.AppendKeyValue(UpstreamOldNamespaceIdentifier, "ns")
		tags.AppendKeyValue(UpstreamNamespaceIdentifier, "ns")
		runtimeResult2.SetTags(tags)

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
				want:    runtimeResult1,
				want1:   true,
				wantErr: false,
			},
			{
				name: "Simple test 2",
				args: args{
					runtime: runtimeDocker,
					pod:     pod2,
				},
				want:    runtimeResult2,
				want1:   true,
				wantErr: false,
			},
		}
		for _, tt := range tests {
			Convey(tt.name, func() {
				got, got1, err := DefaultKubernetesMetadataExtractor(tt.args.runtime, tt.args.pod)
				So(err != nil, ShouldEqual, tt.wantErr)
				if got != nil && got.Tags() != nil {
					So(got.Tags().Tags, ShouldHaveLength, len(tt.want.Tags().Tags))
					for _, tag := range tt.want.Tags().Tags {
						So(got.Tags().Tags, ShouldContain, tag)
					}
				}
				So(got1, ShouldEqual, tt.want1)
			})
		}
	})
}
