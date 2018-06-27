package kubernetesmonitor

import (
	"context"
	"fmt"
	"testing"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	dockermonitor "go.aporeto.io/trireme-lib/monitor/internal/docker"
	"go.aporeto.io/trireme-lib/policy"
	api "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	kubefake "k8s.io/client-go/kubernetes/fake"
	kubecache "k8s.io/client-go/tools/cache"
)

func Test_getKubernetesInformation(t *testing.T) {

	puRuntimeWithTags := func(tags map[string]string) *policy.PURuntime {
		puRuntime := policy.NewPURuntimeWithDefaults()
		puRuntime.SetTags(policy.NewTagStoreFromMap(tags))
		return puRuntime
	}

	type args struct {
		runtime policy.RuntimeReader
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   string
		wantErr bool
	}{
		{
			name:    "no Kubernetes Information",
			args:    args{runtime: policy.NewPURuntimeWithDefaults()},
			want:    "",
			want1:   "",
			wantErr: true,
		},
		{
			name: "both present",
			args: args{runtime: puRuntimeWithTags(map[string]string{
				KubernetesPodNamespaceIdentifier: "a",
				KubernetesPodNameIdentifier:      "b",
			},
			),
			},
			want:    "a",
			want1:   "b",
			wantErr: false,
		},
		{
			name: "both present. NamespaceIdentifier empty",
			args: args{runtime: puRuntimeWithTags(map[string]string{
				KubernetesPodNamespaceIdentifier: "",
				KubernetesPodNameIdentifier:      "b",
			},
			),
			},
			want:    "",
			want1:   "b",
			wantErr: false,
		},
		{
			name: "both present. Name empty",
			args: args{runtime: puRuntimeWithTags(map[string]string{
				KubernetesPodNamespaceIdentifier: "a",
				KubernetesPodNameIdentifier:      "",
			},
			),
			},
			want:    "a",
			want1:   "",
			wantErr: false,
		},
		{
			name: "Namespace missing",
			args: args{runtime: puRuntimeWithTags(map[string]string{
				KubernetesPodNameIdentifier: "b",
			},
			),
			},
			want:    "",
			want1:   "",
			wantErr: true,
		},
		{
			name: "Name missing",
			args: args{runtime: puRuntimeWithTags(map[string]string{
				KubernetesPodNamespaceIdentifier: "a",
			},
			),
			},
			want:    "",
			want1:   "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := getKubernetesInformation(tt.args.runtime)
			if (err != nil) != tt.wantErr {
				t.Errorf("getKubernetesInformation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getKubernetesInformation() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("getKubernetesInformation() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

type mockHandler struct{}

func (m *mockHandler) HandlePUEvent(ctx context.Context, puID string, event common.Event, runtime policy.RuntimeReader) error {
	return nil
}

func TestKubernetesMonitor_HandlePUEvent(t *testing.T) {

	pod1 := &api.Pod{}
	pod1.SetName("pod1")
	pod1.SetNamespace("beer")

	pod1Runtime := policy.NewPURuntimeWithDefaults()
	pod1Runtime.SetTags(policy.NewTagStoreFromMap(map[string]string{
		KubernetesPodNamespaceIdentifier: "beer",
		KubernetesPodNameIdentifier:      "pod1",
	}))

	kubernetesExtractorUnmanaged := func(runtime policy.RuntimeReader, pod *api.Pod) (*policy.PURuntime, bool, error) {
		originalRuntime, ok := runtime.(*policy.PURuntime)
		if !ok {
			return nil, false, fmt.Errorf("Error casting puruntime")
		}

		newRuntime := originalRuntime.Clone()

		return newRuntime, false, nil
	}

	kubernetesExtractorErrored := func(runtime policy.RuntimeReader, pod *api.Pod) (*policy.PURuntime, bool, error) {
		originalRuntime, ok := runtime.(*policy.PURuntime)
		if !ok {
			return nil, false, fmt.Errorf("Error casting puruntime")
		}

		newRuntime := originalRuntime.Clone()

		return newRuntime, false, fmt.Errorf("Previsible error")
	}

	kubernetesExtractorManaged := func(runtime policy.RuntimeReader, pod *api.Pod) (*policy.PURuntime, bool, error) {
		originalRuntime, ok := runtime.(*policy.PURuntime)
		if !ok {
			return nil, false, fmt.Errorf("Error casting puruntime")
		}

		newRuntime := originalRuntime.Clone()

		return newRuntime, true, nil
	}

	type fields struct {
		dockerMonitor       *dockermonitor.DockerMonitor
		kubeClient          kubernetes.Interface
		localNode           string
		handlers            *config.ProcessorConfig
		cache               *cache
		kubernetesExtractor extractors.KubernetesMetadataExtractorType
		podStore            kubecache.Store
		podController       kubecache.Controller
		podControllerStop   chan struct{}
		enableHostPods      bool
	}
	type args struct {
		ctx           context.Context
		puID          string
		event         common.Event
		dockerRuntime policy.RuntimeReader
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:   "empty dockerruntime on create",
			fields: fields{},
			args: args{
				event:         common.EventCreate,
				dockerRuntime: policy.NewPURuntimeWithDefaults(),
			},
			wantErr: true,
		},
		{
			name:   "empty dockerruntime on start",
			fields: fields{},
			args: args{
				event:         common.EventCreate,
				dockerRuntime: policy.NewPURuntimeWithDefaults(),
			},
			wantErr: true,
		},
		{
			name: "Extractor with Unmanaged PU",
			fields: fields{
				kubeClient:          kubefake.NewSimpleClientset(pod1),
				kubernetesExtractor: kubernetesExtractorUnmanaged,
			},
			args: args{
				event:         common.EventCreate,
				dockerRuntime: pod1Runtime,
			},
			wantErr: false,
		},
		{
			name: "Extractor with Errored output",
			fields: fields{
				kubeClient:          kubefake.NewSimpleClientset(pod1),
				kubernetesExtractor: kubernetesExtractorErrored,
			},
			args: args{
				event:         common.EventCreate,
				dockerRuntime: pod1Runtime,
			},
			wantErr: true,
		},
		{
			name: "Extractor with managed PU",
			fields: fields{
				kubeClient:          kubefake.NewSimpleClientset(pod1),
				kubernetesExtractor: kubernetesExtractorManaged,
				cache:               newCache(),
				handlers: &config.ProcessorConfig{
					Policy: &mockHandler{},
				},
			},
			args: args{
				event:         common.EventCreate,
				dockerRuntime: pod1Runtime,
			},
			wantErr: false,
		},
		{
			name: "Destroy not in cache",
			fields: fields{
				kubeClient:          kubefake.NewSimpleClientset(pod1),
				kubernetesExtractor: kubernetesExtractorManaged,
				cache:               newCache(),
				handlers: &config.ProcessorConfig{
					Policy: &mockHandler{},
				},
			},
			args: args{
				event:         common.EventDestroy,
				dockerRuntime: pod1Runtime,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &KubernetesMonitor{
				dockerMonitor:       tt.fields.dockerMonitor,
				kubeClient:          tt.fields.kubeClient,
				localNode:           tt.fields.localNode,
				handlers:            tt.fields.handlers,
				cache:               tt.fields.cache,
				kubernetesExtractor: tt.fields.kubernetesExtractor,
				podStore:            tt.fields.podStore,
				podController:       tt.fields.podController,
				podControllerStop:   tt.fields.podControllerStop,
				enableHostPods:      tt.fields.enableHostPods,
			}
			if err := m.HandlePUEvent(tt.args.ctx, tt.args.puID, tt.args.event, tt.args.dockerRuntime); (err != nil) != tt.wantErr {
				t.Errorf("KubernetesMonitor.HandlePUEvent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKubernetesMonitor_RefreshPUs(t *testing.T) {
	type fields struct {
		dockerMonitor       *dockermonitor.DockerMonitor
		kubeClient          kubernetes.Interface
		localNode           string
		handlers            *config.ProcessorConfig
		cache               *cache
		kubernetesExtractor extractors.KubernetesMetadataExtractorType
		podStore            kubecache.Store
		podController       kubecache.Controller
		podControllerStop   chan struct{}
		enableHostPods      bool
	}
	type args struct {
		ctx context.Context
		pod *api.Pod
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:   "empty pod",
			fields: fields{},
			args: args{
				pod: nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &KubernetesMonitor{
				dockerMonitor:       tt.fields.dockerMonitor,
				kubeClient:          tt.fields.kubeClient,
				localNode:           tt.fields.localNode,
				handlers:            tt.fields.handlers,
				cache:               tt.fields.cache,
				kubernetesExtractor: tt.fields.kubernetesExtractor,
				podStore:            tt.fields.podStore,
				podController:       tt.fields.podController,
				podControllerStop:   tt.fields.podControllerStop,
				enableHostPods:      tt.fields.enableHostPods,
			}
			if err := m.RefreshPUs(tt.args.ctx, tt.args.pod); (err != nil) != tt.wantErr {
				t.Errorf("KubernetesMonitor.RefreshPUs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
