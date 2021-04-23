package k8smonitor

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"go.aporeto.io/enforcerd/internal/extractors/containermetadata"
	"go.aporeto.io/enforcerd/internal/extractors/containermetadata/mockcontainermetadata"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/extractors"
	policy "go.aporeto.io/enforcerd/trireme-lib/policy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetes "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func TestK8sMonitor_updateEvent(t *testing.T) {
	type args struct {
		ctx       context.Context
		sandboxID string
	}
	tests := []struct {
		name              string
		args              args
		wantErr           bool
		metadataExtractor extractors.PodMetadataExtractor
		prepare           func(t *testing.T, mocks *unitTestMonitorMocks)
	}{
		{
			name: "runtime not found for sandbox ID",
			args: args{
				ctx:       context.Background(),
				sandboxID: "not found",
			},
			wantErr: false,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks) {
				mocks.runtimeCache.EXPECT().Get(gomock.Eq("not found")).Return(nil).Times(1)
			},
		},
		{
			name: "runtime found, but pod not found for sandbox ID",
			args: args{
				ctx:       context.Background(),
				sandboxID: "not found",
			},
			wantErr: false,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks) {
				mocks.runtimeCache.EXPECT().Get(gomock.Eq("not found")).Return(policy.NewPURuntimeWithDefaults()).Times(1)
				mocks.podCache.EXPECT().Get(gomock.Eq("not found")).Return(nil).Times(1)
			},
		},
		{
			name: "runtime and pod found, but metadata extraction fails",
			args: args{
				ctx:       context.Background(),
				sandboxID: "sandboxID",
			},
			wantErr: true,
			metadataExtractor: func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error) {
				return nil, fmt.Errorf("error")
			},
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks) {
				mocks.runtimeCache.EXPECT().Get(gomock.Eq("sandboxID")).Return(policy.NewPURuntimeWithDefaults()).Times(1)
				mocks.podCache.EXPECT().Get(gomock.Eq("sandboxID")).Return(&corev1.Pod{}).Times(1)
			},
		},
		{
			name: "runtime and pod found, metadata extraction succeeded, but internal update failed",
			args: args{
				ctx:       context.Background(),
				sandboxID: "sandboxID",
			},
			wantErr: true,
			metadataExtractor: func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error) {
				return policy.NewPURuntimeWithDefaults(), nil
			},
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks) {
				mocks.runtimeCache.EXPECT().Get(gomock.Eq("sandboxID")).Return(policy.NewPURuntimeWithDefaults()).Times(1)
				mocks.podCache.EXPECT().Get(gomock.Eq("sandboxID")).Return(&corev1.Pod{}).Times(1)
				mocks.runtimeCache.EXPECT().Set(gomock.Eq("sandboxID"), gomock.Eq(policy.NewPURuntimeWithDefaults())).Return(fmt.Errorf("error")).Times(1)
			},
		},
		{
			name: "update event fails in policy engine",
			args: args{
				ctx:       context.Background(),
				sandboxID: "sandboxID",
			},
			wantErr: true,
			metadataExtractor: func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error) {
				return policy.NewPURuntimeWithDefaults(), nil
			},
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks) {
				mocks.runtimeCache.EXPECT().Get(gomock.Eq("sandboxID")).Return(policy.NewPURuntimeWithDefaults()).Times(1)
				mocks.podCache.EXPECT().Get(gomock.Eq("sandboxID")).Return(&corev1.Pod{}).Times(1)
				mocks.runtimeCache.EXPECT().Set(gomock.Eq("sandboxID"), gomock.Eq(policy.NewPURuntimeWithDefaults())).Return(nil).Times(1)
				mocks.policy.EXPECT().HandlePUEvent(
					gomock.Any(),
					gomock.Eq("sandboxID"),
					gomock.Eq(common.EventUpdate),
					gomock.Eq(policy.NewPURuntimeWithDefaults()),
				).Return(fmt.Errorf("error")).Times(1)
			},
		},
		{
			name: "update event succeeds",
			args: args{
				ctx:       context.Background(),
				sandboxID: "sandboxID",
			},
			wantErr: false,
			metadataExtractor: func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error) {
				return policy.NewPURuntimeWithDefaults(), nil
			},
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks) {
				mocks.runtimeCache.EXPECT().Get(gomock.Eq("sandboxID")).Return(policy.NewPURuntimeWithDefaults()).Times(1)
				mocks.podCache.EXPECT().Get(gomock.Eq("sandboxID")).Return(&corev1.Pod{}).Times(1)
				mocks.runtimeCache.EXPECT().Set(gomock.Eq("sandboxID"), gomock.Eq(policy.NewPURuntimeWithDefaults())).Return(nil).Times(1)
				mocks.policy.EXPECT().HandlePUEvent(
					gomock.Any(),
					gomock.Eq("sandboxID"),
					gomock.Eq(common.EventUpdate),
					gomock.Eq(policy.NewPURuntimeWithDefaults()),
				).Return(nil).Times(1)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m, mocks := newUnitTestMonitor(ctrl)
			m.metadataExtractor = tt.metadataExtractor
			tt.prepare(t, mocks)
			if err := m.updateEvent(tt.args.ctx, tt.args.sandboxID); (err != nil) != tt.wantErr {
				t.Errorf("K8sMonitor.updateEvent() error = %v, wantErr %v", err, tt.wantErr)
			}
			ctrl.Finish()
		})
	}
}

func TestK8sMonitor_stopEvent(t *testing.T) {
	type args struct {
		ctx       context.Context
		sandboxID string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		prepare func(t *testing.T, mocks *unitTestMonitorMocks)
	}{
		{
			name: "runtime not found for sandbox ID",
			args: args{
				ctx:       context.Background(),
				sandboxID: "not found",
			},
			wantErr: false,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks) {
				mocks.runtimeCache.EXPECT().Get(gomock.Eq("not found")).Return(nil).Times(1)
			},
		},
		{
			name: "stop event failed in policy engine",
			args: args{
				ctx:       context.Background(),
				sandboxID: "sandboxID",
			},
			wantErr: true,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks) {
				mocks.runtimeCache.EXPECT().Get(gomock.Eq("sandboxID")).Return(policy.NewPURuntimeWithDefaults()).Times(1)
				mocks.policy.EXPECT().HandlePUEvent(
					gomock.Any(),
					gomock.Eq("sandboxID"),
					gomock.Eq(common.EventStop),
					gomock.Eq(policy.NewPURuntimeWithDefaults()),
				).Return(fmt.Errorf("error")).Times(1)
			},
		},
		{
			name: "stop event succeeds",
			args: args{
				ctx:       context.Background(),
				sandboxID: "sandboxID",
			},
			wantErr: false,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks) {
				mocks.runtimeCache.EXPECT().Get(gomock.Eq("sandboxID")).Return(policy.NewPURuntimeWithDefaults()).Times(1)
				mocks.policy.EXPECT().HandlePUEvent(
					gomock.Any(),
					gomock.Eq("sandboxID"),
					gomock.Eq(common.EventStop),
					gomock.Eq(policy.NewPURuntimeWithDefaults()),
				).Return(nil).Times(1)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m, mocks := newUnitTestMonitor(ctrl)
			tt.prepare(t, mocks)
			if err := m.stopEvent(tt.args.ctx, tt.args.sandboxID); (err != nil) != tt.wantErr {
				t.Errorf("K8sMonitor.stopEvent() error = %v, wantErr %v", err, tt.wantErr)
			}
			ctrl.Finish()
		})
	}
}

func TestK8sMonitor_destroyEvent(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
		prepare func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata)
	}{
		{
			name:    "unexpected container kind",
			wantErr: true,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.Container).Times(2)
			},
		},
		{
			name:    "nothing happens for a PodContainer",
			wantErr: false,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodContainer).Times(1)
			},
		},
		{
			name:    "PodSandbox not found in cache",
			wantErr: false,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodSandbox).Times(1)
				kmd.EXPECT().ID().Return("sandboxID").Times(2)
				mocks.runtimeCache.EXPECT().Get(gomock.Eq("sandboxID")).Return(nil).Times(1)
			},
		},
		{
			name:    "destroy event failed in policy engine",
			wantErr: true,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodSandbox).Times(1)
				kmd.EXPECT().ID().Return("sandboxID").Times(5)
				mocks.runtimeCache.EXPECT().Get(gomock.Eq("sandboxID")).Return(policy.NewPURuntimeWithDefaults()).Times(1)
				mocks.runtimeCache.EXPECT().Delete(gomock.Eq("sandboxID")).Times(1)
				mocks.podCache.EXPECT().Delete(gomock.Eq("sandboxID")).Times(1)
				mocks.policy.EXPECT().HandlePUEvent(
					gomock.Any(),
					gomock.Eq("sandboxID"),
					gomock.Eq(common.EventDestroy),
					gomock.Eq(policy.NewPURuntimeWithDefaults()),
				).Return(fmt.Errorf("error")).Times(1)
			},
		},
		{
			name:    "destroy event succeeds",
			wantErr: false,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodSandbox).Times(1)
				kmd.EXPECT().ID().Return("sandboxID").Times(5)
				mocks.runtimeCache.EXPECT().Get(gomock.Eq("sandboxID")).Return(policy.NewPURuntimeWithDefaults()).Times(1)
				mocks.runtimeCache.EXPECT().Delete(gomock.Eq("sandboxID")).Times(1)
				mocks.podCache.EXPECT().Delete(gomock.Eq("sandboxID")).Times(1)
				mocks.policy.EXPECT().HandlePUEvent(
					gomock.Any(),
					gomock.Eq("sandboxID"),
					gomock.Eq(common.EventDestroy),
					gomock.Eq(policy.NewPURuntimeWithDefaults()),
				).Return(nil).Times(1)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m, mocks := newUnitTestMonitor(ctrl)
			kmd := mockcontainermetadata.NewMockCommonKubernetesContainerMetadata(ctrl)
			tt.prepare(t, mocks, kmd)
			if err := m.destroyEvent(context.Background(), kmd); (err != nil) != tt.wantErr {
				t.Errorf("K8sMonitor.destroyEvent() error = %v, wantErr %v", err, tt.wantErr)
			}
			ctrl.Finish()
		})
	}
}

func TestK8sMonitor_startEvent(t *testing.T) {
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

	tests := []struct {
		name              string
		wantErr           bool
		metadataExtractor extractors.PodMetadataExtractor
		kubeClient        kubernetes.Interface
		prepare           func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata)
	}{
		{
			name:    "unexpected container kind",
			wantErr: true,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.Container).Times(2)
			},
		},
		{
			name:    "PodContainer: is simply being ignored",
			wantErr: false,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodContainer).Times(1)
				kmd.EXPECT().ID().Return("containerID").Times(1)
				kmd.EXPECT().PodSandboxID().Return("sandboxID").Times(1)
				kmd.EXPECT().PodName().Return("my-pod").Times(1)
				kmd.EXPECT().PodNamespace().Return("default").Times(1)
			},
		},
		{
			name:       "PodSandbox: failed to get pod from API",
			wantErr:    true,
			kubeClient: c,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodSandbox).Times(1)
				kmd.EXPECT().ID().Return("sandboxID").Times(1)
				kmd.EXPECT().PodName().Return("not-found").Times(2)
				kmd.EXPECT().PodNamespace().Return("default").Times(2)
			},
		},
		{
			name:       "PodSandbox: got pod from API, but failed to update cache",
			wantErr:    true,
			kubeClient: c,
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodSandbox).Times(1)
				kmd.EXPECT().ID().Return("sandboxID").Times(2)
				kmd.EXPECT().PodName().Return("my-pod").Times(2)
				kmd.EXPECT().PodNamespace().Return("default").Times(2)
				mocks.podCache.EXPECT().Set(gomock.Eq("sandboxID"), gomock.Eq(podTemplate1.DeepCopy())).Return(fmt.Errorf("error")).Times(1)
			},
		},
		{
			name:       "PodSandbox: metadata extraction fails",
			wantErr:    true,
			kubeClient: c,
			metadataExtractor: func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error) {
				return nil, fmt.Errorf("error")
			},
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodSandbox).Times(1)
				kmd.EXPECT().ID().Return("sandboxID").Times(2)
				kmd.EXPECT().PodName().Return("my-pod").Times(2)
				kmd.EXPECT().PodNamespace().Return("default").Times(2)
				kmd.EXPECT().NetNSPath().Return("/var/run/netns/container1")
				mocks.podCache.EXPECT().Set(gomock.Eq("sandboxID"), gomock.Eq(podTemplate1.DeepCopy())).Return(nil).Times(1)
			},
		},
		{
			name:       "PodSandbox: metadata extraction succeeds, but updating cache fails",
			wantErr:    true,
			kubeClient: c,
			metadataExtractor: func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error) {
				return policy.NewPURuntimeWithDefaults(), nil
			},
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodSandbox).Times(1)
				kmd.EXPECT().ID().Return("sandboxID").Times(3)
				kmd.EXPECT().PodName().Return("my-pod").Times(2)
				kmd.EXPECT().PodNamespace().Return("default").Times(2)
				kmd.EXPECT().NetNSPath().Return("/var/run/netns/container1")
				mocks.podCache.EXPECT().Set(gomock.Eq("sandboxID"), gomock.Eq(podTemplate1.DeepCopy())).Return(nil).Times(1)
				mocks.runtimeCache.EXPECT().Set(gomock.Eq("sandboxID"), gomock.Eq(policy.NewPURuntimeWithDefaults())).Return(fmt.Errorf("error")).Times(1)
			},
		},
		{
			name:       "PodSandbox: HostNetwork pods are being ignored",
			wantErr:    false,
			kubeClient: c,
			metadataExtractor: func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error) {
				return nil, fmt.Errorf("we should not get here")
			},
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodSandbox).Times(1)
				kmd.EXPECT().ID().Return("sandboxID").Times(1)
				kmd.EXPECT().PodName().Return("my-host-network-pod").Times(2)
				kmd.EXPECT().PodNamespace().Return("default").Times(2)
				//mocks.podCache.EXPECT().Set(gomock.Eq("sandboxID"), gomock.Eq(podTemplate2.DeepCopy())).Return(nil).Times(1)
			},
		},
		{
			name:       "PodSandbox: start event fails in policy engine",
			wantErr:    true,
			kubeClient: c,
			metadataExtractor: func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error) {
				return policy.NewPURuntimeWithDefaults(), nil
			},
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodSandbox).Times(1)
				kmd.EXPECT().ID().Return("sandboxID").Times(4)
				kmd.EXPECT().PodName().Return("my-pod").Times(2)
				kmd.EXPECT().PodNamespace().Return("default").Times(2)
				kmd.EXPECT().NetNSPath().Return("/var/run/netns/container1")
				mocks.podCache.EXPECT().Set(gomock.Eq("sandboxID"), gomock.Eq(podTemplate1.DeepCopy())).Return(nil).Times(1)
				mocks.runtimeCache.EXPECT().Set(gomock.Eq("sandboxID"), gomock.Eq(policy.NewPURuntimeWithDefaults())).Return(nil).Times(1)
				mocks.policy.EXPECT().HandlePUEvent(
					gomock.Any(),
					gomock.Eq("sandboxID"),
					gomock.Eq(common.EventStart),
					gomock.Eq(policy.NewPURuntimeWithDefaults()),
				).Return(fmt.Errorf("error")).Times(1)
			},
		},
		{
			name:       "PodSandbox: start event succeeds",
			wantErr:    false,
			kubeClient: c,
			metadataExtractor: func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error) {
				return policy.NewPURuntimeWithDefaults(), nil
			},
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodSandbox).Times(1)
				kmd.EXPECT().ID().Return("sandboxID").Times(4)
				kmd.EXPECT().PodName().Return("my-pod").Times(2)
				kmd.EXPECT().PodNamespace().Return("default").Times(2)
				kmd.EXPECT().NetNSPath().Return("/var/run/netns/container1")
				mocks.podCache.EXPECT().Set(gomock.Eq("sandboxID"), gomock.Eq(podTemplate1.DeepCopy())).Return(nil).Times(1)
				mocks.runtimeCache.EXPECT().Set(gomock.Eq("sandboxID"), gomock.Eq(policy.NewPURuntimeWithDefaults())).Return(nil).Times(1)
				mocks.policy.EXPECT().HandlePUEvent(
					gomock.Any(),
					gomock.Eq("sandboxID"),
					gomock.Eq(common.EventStart),
					gomock.Eq(policy.NewPURuntimeWithDefaults()),
				).Return(nil).Times(1)
			},
		},
	}
	for _, tt := range tests {
		ctx, cancel := context.WithCancel(context.Background())
		ctrl := gomock.NewController(t)
		m, mocks := newUnitTestMonitor(ctrl)
		m.metadataExtractor = tt.metadataExtractor
		kmd := mockcontainermetadata.NewMockCommonKubernetesContainerMetadata(ctrl)
		m.kubeClient = tt.kubeClient
		if m.kubeClient != nil {
			m.podLister = setupInformerForUnitTests(ctx, m.kubeClient, m.nodename)
		}
		tt.prepare(t, mocks, kmd)
		t.Run(tt.name, func(t *testing.T) {
			if err := m.startEvent(ctx, kmd, 0); (err != nil) != tt.wantErr {
				t.Errorf("K8sMonitor.startEvent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
		ctrl.Finish()
		cancel()
	}
}

func TestK8sMonitor_Event(t *testing.T) {
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

	type args struct {
		ctx  context.Context
		ev   common.Event
		data interface{}
	}
	tests := []struct {
		name              string
		args              args
		metadataExtractor extractors.PodMetadataExtractor
		kubeClient        kubernetes.Interface
		prepare           func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata)
		wantErr           bool
	}{
		{
			name: "unexpected event",
			args: args{
				ctx: context.Background(),
				ev:  common.EventPause,
			},
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
			},
			wantErr: true,
		},
		{
			name: "unexpected event data",
			args: args{
				ctx:  context.Background(),
				ev:   common.EventPause,
				data: "wrong type",
			},
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
			},
			wantErr: true,
		},
		{
			name: "failing start event",
			args: args{
				ctx: context.Background(),
				ev:  common.EventStart,
			},
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.Container).Times(2)
			},
			wantErr: true,
		},
		{
			name:       "successful start event for sandbox for pod",
			kubeClient: c,
			metadataExtractor: func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error) {
				return policy.NewPURuntimeWithDefaults(), nil
			},
			args: args{
				ctx: context.Background(),
				ev:  common.EventStart,
			},
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodSandbox).Times(1)
				kmd.EXPECT().ID().Return("sandboxID").Times(4)
				kmd.EXPECT().PodName().Return("my-pod").Times(2)
				kmd.EXPECT().PodNamespace().Return("default").Times(2)
				kmd.EXPECT().NetNSPath().Return("/var/run/netns/container1")
				mocks.podCache.EXPECT().Set(gomock.Eq("sandboxID"), gomock.Eq(podTemplate1.DeepCopy())).Return(nil).Times(1)
				mocks.runtimeCache.EXPECT().Set(gomock.Eq("sandboxID"), gomock.Eq(policy.NewPURuntimeWithDefaults())).Return(nil).Times(1)
				mocks.policy.EXPECT().HandlePUEvent(
					gomock.Any(),
					gomock.Eq("sandboxID"),
					gomock.Eq(common.EventStart),
					gomock.Eq(policy.NewPURuntimeWithDefaults()),
				).Return(nil).Times(1)
			},
		},
		{
			name: "failing destroy event",
			args: args{
				ctx: context.Background(),
				ev:  common.EventDestroy,
			},
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.Container).Times(2)
			},
			wantErr: true,
		},
		{
			name:    "successful destroy event for sandbox for pod",
			wantErr: false,
			args: args{
				ctx: context.Background(),
				ev:  common.EventDestroy,
			},
			prepare: func(t *testing.T, mocks *unitTestMonitorMocks, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodSandbox).Times(1)
				kmd.EXPECT().ID().Return("sandboxID").Times(5)
				mocks.runtimeCache.EXPECT().Get(gomock.Eq("sandboxID")).Return(policy.NewPURuntimeWithDefaults()).Times(1)
				mocks.runtimeCache.EXPECT().Delete(gomock.Eq("sandboxID")).Times(1)
				mocks.podCache.EXPECT().Delete(gomock.Eq("sandboxID")).Times(1)
				mocks.policy.EXPECT().HandlePUEvent(
					gomock.Any(),
					gomock.Eq("sandboxID"),
					gomock.Eq(common.EventDestroy),
					gomock.Eq(policy.NewPURuntimeWithDefaults()),
				).Return(nil).Times(1)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(tt.args.ctx)
			ctrl := gomock.NewController(t)
			m, mocks := newUnitTestMonitor(ctrl)
			m.metadataExtractor = tt.metadataExtractor
			kmd := mockcontainermetadata.NewMockCommonKubernetesContainerMetadata(ctrl)
			m.kubeClient = tt.kubeClient
			if m.kubeClient != nil {
				m.podLister = setupInformerForUnitTests(ctx, m.kubeClient, m.nodename)
			}
			tt.prepare(t, mocks, kmd)
			var data interface{}
			if tt.args.data != nil {
				data = tt.args.data
			} else {
				data = kmd
			}
			if err := m.Event(ctx, tt.args.ev, data); (err != nil) != tt.wantErr {
				t.Errorf("K8sMonitor.Event() error = %v, wantErr %v", err, tt.wantErr)
			}
			ctrl.Finish()
			cancel()
		})
	}
}
