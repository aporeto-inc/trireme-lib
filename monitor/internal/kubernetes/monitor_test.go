// +build !windows

package kubernetesmonitor

import (
	"testing"

	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	dockermonitor "go.aporeto.io/trireme-lib/monitor/internal/docker"
	"go.aporeto.io/trireme-lib/monitor/registerer"
	"k8s.io/client-go/kubernetes"
	kubecache "k8s.io/client-go/tools/cache"
)

func TestKubernetesMonitor_SetupConfig(t *testing.T) {

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
		registerer registerer.Registerer
		cfg        interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:   "random config",
			fields: fields{},
			args: args{
				registerer: nil,
				cfg:        "123",
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
			if err := m.SetupConfig(tt.args.registerer, tt.args.cfg); (err != nil) != tt.wantErr {
				t.Errorf("KubernetesMonitor.SetupConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
