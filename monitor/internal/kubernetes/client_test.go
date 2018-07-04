package kubernetesmonitor

import (
	"reflect"
	"testing"

	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	dockermonitor "go.aporeto.io/trireme-lib/monitor/internal/docker"
	api "k8s.io/api/core/v1"
	kubefields "k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	kubefake "k8s.io/client-go/kubernetes/fake"
	kubecache "k8s.io/client-go/tools/cache"
)

func TestNewKubeClient(t *testing.T) {
	type args struct {
		kubeconfig string
	}
	tests := []struct {
		name    string
		args    args
		want    *kubernetes.Clientset
		wantErr bool
	}{
		{
			name: "test1",
			args: args{
				kubeconfig: "/tmp/abcd",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewKubeClient(tt.args.kubeconfig)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewKubeClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewKubeClient() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKubernetesMonitor_Pod(t *testing.T) {

	pod1 := &api.Pod{}
	pod1.SetName("pod1")
	pod1.SetNamespace("beer")

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
		podName   string
		namespace string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *api.Pod
		wantErr bool
	}{
		{
			name: "Query existing pod",
			fields: fields{
				kubeClient: kubefake.NewSimpleClientset(pod1),
			},
			args: args{
				podName:   "pod1",
				namespace: "beer",
			},
			want:    pod1,
			wantErr: false,
		},
		{
			name: "Query non existing pod",
			fields: fields{
				kubeClient: kubefake.NewSimpleClientset(pod1),
			},
			args: args{
				podName:   "pod2",
				namespace: "beer",
			},
			want:    nil,
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
			got, err := m.Pod(tt.args.podName, tt.args.namespace)
			if (err != nil) != tt.wantErr {
				t.Errorf("KubernetesMonitor.Pod() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KubernetesMonitor.Pod() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKubernetesMonitor_localNodeSelector(t *testing.T) {
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
	tests := []struct {
		name   string
		fields fields
		want   kubefields.Selector
	}{
		{
			name: "Normal string",
			fields: fields{
				localNode: "abc",
			},
			want: kubefields.Set(map[string]string{
				"spec.nodeName": "abc",
			}).AsSelector(),
		},
		{
			name: "Empty string",
			fields: fields{
				localNode: "",
			},
			want: kubefields.Set(map[string]string{
				"spec.nodeName": "",
			}).AsSelector(),
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
			if got := m.localNodeSelector(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KubernetesMonitor.localNodeSelector() = %v, want %v", got, tt.want)
			}
		})
	}
}
