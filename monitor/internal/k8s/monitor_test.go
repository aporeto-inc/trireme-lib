package k8smonitor

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/config"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/constants"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/external"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/external/mockexternal"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/extractors"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/registerer"
	policy "go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/policy/mockpolicy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cri/mockcri"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetes "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

func TestK8sMonitor_SetupConfig(t *testing.T) {
	type args struct {
		registerer registerer.Registerer
		cfg        interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "wrong config type",
			args: args{
				registerer: nil,
				cfg:        "wrong type",
			},
			wantErr: true,
		},
		{
			name: "default config is not workable",
			args: args{
				registerer: nil,
				cfg:        nil,
			},
			wantErr: true,
		},
		{
			name: "config: missing metadataExtractor",
			args: args{
				registerer: nil,
				cfg: &Config{
					MetadataExtractor: nil,
				},
			},
			wantErr: true,
		},
		{
			name: "config: missing netclsProgrammer",
			args: args{
				registerer: nil,
				cfg: &Config{
					MetadataExtractor: func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error) {
						return nil, nil
					},
				},
			},
			wantErr: true,
		},
		{
			name: "config: missing sandboxExtractor",
			args: args{
				registerer: nil,
				cfg: &Config{
					MetadataExtractor: func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error) {
						return nil, nil
					},
				},
			},
			wantErr: true,
		},
		{
			name: "config: missing resetNetcls",
			args: args{
				registerer: nil,
				cfg: &Config{
					MetadataExtractor: func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error) {
						return nil, nil
					},
				},
			},
			wantErr: true,
		},
		{
			name: "config: missing CRI runtime service",
			args: args{
				registerer: nil,
				cfg: &Config{
					MetadataExtractor: func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error) {
						return nil, nil
					},
					CRIRuntimeService: nil,
				},
			},
			wantErr: true,
		},
		{
			name: "config: missing CRI runtime service",
			args: args{
				registerer: nil,
				cfg: &Config{
					MetadataExtractor: func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error) {
						return nil, nil
					},
					CRIRuntimeService: nil,
				},
			},
			wantErr: true,
		},
		{
			name: "kubeClient: in-cluster config fails",
			args: args{
				registerer: nil,
				cfg: &Config{
					MetadataExtractor: func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error) {
						return nil, nil
					},
					CRIRuntimeService: mockcri.NewMockExtendedRuntimeService(nil),
					Nodename:          "",
					Kubeconfig:        "",
				},
			},
			wantErr: true,
		},
		{
			name: "kubeClient: non-existent kubeconfig fails",
			args: args{
				registerer: nil,
				cfg: &Config{
					MetadataExtractor: func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error) {
						return nil, nil
					},
					CRIRuntimeService: mockcri.NewMockExtendedRuntimeService(nil),
					Nodename:          "",
					Kubeconfig:        "does-not-exist",
				},
			},
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				registerer: nil,
				cfg: &Config{
					MetadataExtractor: func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error) {
						return nil, nil
					},
					CRIRuntimeService: mockcri.NewMockExtendedRuntimeService(nil),
					Nodename:          "",
					Kubeconfig:        "testdata/kubeconfig",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			m := New(ctx)
			if err := m.SetupConfig(tt.args.registerer, tt.args.cfg); (err != nil) != tt.wantErr {
				t.Errorf("k8sMonitor.SetupConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			cancel()
		})
	}
}

func TestK8sMonitor_Resync(t *testing.T) {
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "unimplemented",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			m := New(ctx)
			if err := m.Resync(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("k8sMonitor.Resync() error = %v, wantErr %v", err, tt.wantErr)
			}
			cancel()
		})
	}
}

func TestK8sMonitor_SetupHandlers(t *testing.T) {
	type args struct {
		c *config.ProcessorConfig
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "arguments must be set 1-to-1 in monitor: nil",
			args: args{
				c: nil,
			},
		},
		{
			name: "arguments must be set 1-to-1 in monitor: simple handler",
			args: args{
				c: &config.ProcessorConfig{
					Collector: collector.NewDefaultCollector(),
					Policy:    mockpolicy.NewMockResolver(nil),
					ExternalEventSender: []external.ReceiverRegistration{
						mockexternal.NewMockReceiverRegistration(nil),
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			m := New(ctx)
			m.SetupHandlers(tt.args.c)
			if !reflect.DeepEqual(m.handlers, tt.args.c) {
				t.Errorf("m.handlers %v, want %v", m.handlers, tt.args.c)
			}
			cancel()
		})
	}
}

func TestK8sMonitor_Run(t *testing.T) {
	podTemplate1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			NodeName: "test",
		},
	}
	podTemplate2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-host-network-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			HostNetwork: true,
			NodeName:    "test",
		},
	}
	c := fake.NewSimpleClientset(
		podTemplate1.DeepCopy(),
		podTemplate2.DeepCopy(),
	)
	type fields struct {
		collector                collector.EventCollector
		unsetExternalEventSender bool
		kubeClient               kubernetes.Interface
		metadataExtractor        extractors.PodMetadataExtractor
		nodename                 string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
		prepare func(t *testing.T, mocks *unitTestMonitorMocks)
	}{
		{
			name: "no kubeClient",
			fields: fields{
				kubeClient: nil,
			},
			wantErr: true,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks) {
			},
		},
		{
			name: "handlers setup is incomplete",
			fields: fields{
				collector:  nil,
				kubeClient: c,
			},
			wantErr: true,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks) {
			},
		},
		{
			name: "ExternalEventSender is not set",
			fields: fields{
				collector:                collector.NewDefaultCollector(),
				unsetExternalEventSender: true,
				kubeClient:               c,
			},
			wantErr: true,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks) {
			},
		},
		{
			name: "ReceiverRegistration fails: unavailable",
			fields: fields{
				collector:                collector.NewDefaultCollector(),
				unsetExternalEventSender: false,
				kubeClient:               c,
				nodename:                 "test",
			},
			wantErr: true,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks) {
				mocks.podCache.EXPECT().SetupInformer(
					gomock.Any(),
					gomock.Eq(c),
					gomock.Eq("test"),
					gomock.AssignableToTypeOf(defaultNeedsUpdate),
				)
				mocks.externalEventSender.EXPECT().SenderName().Return("random").Times(1)
			},
		},
		{
			name: "ReceiverRegistration fails: Register call fails",
			fields: fields{
				collector:                collector.NewDefaultCollector(),
				unsetExternalEventSender: false,
				kubeClient:               c,
				nodename:                 "test",
			},
			wantErr: true,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks) {
				mocks.podCache.EXPECT().SetupInformer(
					gomock.Any(),
					gomock.Eq(c),
					gomock.Eq("test"),
					gomock.AssignableToTypeOf(defaultNeedsUpdate),
				)
				mocks.externalEventSender.EXPECT().SenderName().Return(constants.MonitorExtSenderName).Times(1)
				mocks.externalEventSender.EXPECT().Register(
					gomock.Eq(constants.K8sMonitorRegistrationName),
					gomock.AssignableToTypeOf(&K8sMonitor{}),
				).Return(fmt.Errorf("error")).Times(1)
			},
		},
		{
			name: "Listing Sandboxes from CRI fails",
			fields: fields{
				collector:                collector.NewDefaultCollector(),
				unsetExternalEventSender: false,
				kubeClient:               c,
				nodename:                 "test",
			},
			wantErr: true,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks) {
				mocks.externalEventSender.EXPECT().SenderName().Return(constants.MonitorExtSenderName).Times(1)
				mocks.externalEventSender.EXPECT().Register(
					gomock.Eq(constants.K8sMonitorRegistrationName),
					gomock.AssignableToTypeOf(&K8sMonitor{}),
				).Return(nil).Times(1)
				mocks.podCache.EXPECT().SetupInformer(
					gomock.Any(),
					gomock.Eq(c),
					gomock.Eq("test"),
					gomock.AssignableToTypeOf(defaultNeedsUpdate),
				)
				mocks.cri.EXPECT().ListPodSandbox(gomock.Eq(&runtimeapi.PodSandboxFilter{
					State: &runtimeapi.PodSandboxStateValue{
						State: runtimeapi.PodSandboxState_SANDBOX_READY,
					},
				})).Return(nil, fmt.Errorf("error")).Times(1)
			},
		},
		{
			name: "monitor starts successful with empty sandbox list from CRI",
			fields: fields{
				collector:                collector.NewDefaultCollector(),
				unsetExternalEventSender: false,
				kubeClient:               c,
				nodename:                 "test",
			},
			wantErr: false,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks) {
				mocks.externalEventSender.EXPECT().SenderName().Return(constants.MonitorExtSenderName).Times(1)
				mocks.externalEventSender.EXPECT().Register(
					gomock.Eq(constants.K8sMonitorRegistrationName),
					gomock.AssignableToTypeOf(&K8sMonitor{}),
				).Return(nil).Times(1)
				mocks.podCache.EXPECT().SetupInformer(
					gomock.Any(),
					gomock.Eq(c),
					gomock.Eq("test"),
					gomock.AssignableToTypeOf(defaultNeedsUpdate),
				)
				mocks.cri.EXPECT().ListPodSandbox(gomock.Eq(&runtimeapi.PodSandboxFilter{
					State: &runtimeapi.PodSandboxStateValue{
						State: runtimeapi.PodSandboxState_SANDBOX_READY,
					},
				})).Return(
					[]*runtimeapi.PodSandbox{},
					nil,
				).Times(1)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m, mocks := newUnitTestMonitor(ctrl)
			m.SenderReady()
			m.handlers.Collector = tt.fields.collector
			if tt.fields.unsetExternalEventSender {
				m.handlers.ExternalEventSender = nil
			}
			m.kubeClient = tt.fields.kubeClient
			m.metadataExtractor = tt.fields.metadataExtractor
			m.nodename = tt.fields.nodename
			tt.prepare(t, mocks)
			if err := m.Run(context.Background()); (err != nil) != tt.wantErr {
				t.Errorf("k8sMonitor.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
			ctrl.Finish()
		})
	}
}
