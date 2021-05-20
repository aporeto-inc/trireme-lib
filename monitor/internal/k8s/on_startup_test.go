package k8smonitor

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/golang/mock/gomock"

	"go.aporeto.io/enforcerd/internal/extractors/containermetadata"
	"go.aporeto.io/enforcerd/internal/extractors/containermetadata/mockcontainermetadata"

	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"

	"go.aporeto.io/enforcerd/trireme-lib/monitor/config"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cri/mockcri"
)

func Test_extractKmdFromCRISandbox(t *testing.T) {

	type args struct {
		sandboxID string
	}
	tests := []struct {
		name    string
		args    args
		want    containermetadata.CommonKubernetesContainerMetadata
		wantErr bool
		prepare func(t *testing.T, extractor *mockcontainermetadata.MockCommonContainerMetadataExtractor)
	}{
		{
			name: "sandbox ID empty",
			args: args{
				sandboxID: "",
			},
			want:    nil,
			wantErr: true,
			prepare: func(t *testing.T, extractor *mockcontainermetadata.MockCommonContainerMetadataExtractor) {
				//nothing to be done here
			},
		},
		{
			name: "container not found with the extractor",
			args: args{
				sandboxID: "not-found",
			},
			want:    nil,
			wantErr: true,
			prepare: func(t *testing.T, extractor *mockcontainermetadata.MockCommonContainerMetadataExtractor) {
				extractor.EXPECT().Has(
					gomock.Eq(containermetadata.NewRuncArguments(containermetadata.StartAction, "not-found")),
				).Return(false).Times(1)
			},
		},
		{
			name: "container extractor failed",
			args: args{
				sandboxID: "sandbox-id",
			},
			want:    nil,
			wantErr: true,
			prepare: func(t *testing.T, extractor *mockcontainermetadata.MockCommonContainerMetadataExtractor) {
				ContainerArgs := containermetadata.NewRuncArguments(containermetadata.StartAction, "sandbox-id")
				extractor.EXPECT().Has(gomock.Eq(ContainerArgs)).Return(true).Times(1)
				extractor.EXPECT().Extract(gomock.Eq(ContainerArgs)).Return(nil, nil, fmt.Errorf("failed to extrat")).Times(1)
			},
		},
		{
			name: "container extractor succeeded but is not Kubernetes container",
			args: args{
				sandboxID: "sandbox-id",
			},
			want:    nil,
			wantErr: true,
			prepare: func(t *testing.T, extractor *mockcontainermetadata.MockCommonContainerMetadataExtractor) {
				ContainerArgs := containermetadata.NewRuncArguments(containermetadata.StartAction, "sandbox-id")
				extractor.EXPECT().Has(gomock.Eq(ContainerArgs)).Return(true).Times(1)
				// technically the first result would need to be populated, but that doesn't matter for the test
				extractor.EXPECT().Extract(gomock.Eq(ContainerArgs)).Return(nil, nil, nil).Times(1)
			},
		},
		{
			name: "container extractor succeeded",
			args: args{
				sandboxID: "sandbox-id",
			},
			want:    mockcontainermetadata.NewMockCommonKubernetesContainerMetadata(nil),
			wantErr: false,
			prepare: func(t *testing.T, extractor *mockcontainermetadata.MockCommonContainerMetadataExtractor) {
				ContainerArgs := containermetadata.NewRuncArguments(containermetadata.StartAction, "sandbox-id")
				extractor.EXPECT().Has(gomock.Eq(ContainerArgs)).Return(true).Times(1)
				// technically the first result would need to be populated, but that doesn't matter for the test
				extractor.EXPECT().Extract(gomock.Eq(ContainerArgs)).Return(
					nil,
					mockcontainermetadata.NewMockCommonKubernetesContainerMetadata(nil),
					nil,
				).Times(1)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockExtractor := mockcontainermetadata.NewMockCommonContainerMetadataExtractor(ctrl)
			extractor = mockExtractor
			tt.prepare(t, mockExtractor)
			got, err := extractKmdFromCRISandbox(tt.args.sandboxID)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractKmdFromCRISandbox() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractKmdFromCRISandbox() = %v, want %v", got, tt.want)
			}
			ctrl.Finish()
		})
	}
}

type unitTestStartEvent interface {
	f() startEventFunc
	wait()
	called() bool
}
type unitTestStartEventHandler struct {
	sync.RWMutex
	wg        sync.WaitGroup
	wgCounter int
	wasCalled bool
	err       error
}

func (h *unitTestStartEventHandler) startEvent(ctx context.Context, kmd containermetadata.CommonKubernetesContainerMetadata, retry uint) error {
	h.Lock()
	defer h.Unlock()
	h.wasCalled = true
	if h.wgCounter > 0 {
		h.wgCounter--
	}
	if h.wgCounter >= 0 {
		h.wg.Done()
	}
	return h.err
}

func (h *unitTestStartEventHandler) f() startEventFunc {
	return h.startEvent
}

func (h *unitTestStartEventHandler) wait() {
	h.wg.Wait()
}

func (h *unitTestStartEventHandler) called() bool {
	h.RLock()
	defer h.RUnlock()
	return h.wasCalled
}

func newUnitTestStartEventHandler(n int, err error) unitTestStartEvent {
	h := &unitTestStartEventHandler{
		err:       err,
		wgCounter: n,
	}
	h.wg.Add(n)
	return h
}

func TestK8sMonitor_onStartup(t *testing.T) {

	listSandboxFilter := &runtimeapi.PodSandboxFilter{
		State: &runtimeapi.PodSandboxStateValue{
			State: runtimeapi.PodSandboxState_SANDBOX_READY,
		},
	}

	tests := []struct {
		name               string
		startEventHandler  unitTestStartEvent
		wantErr            bool
		prepare            func(t *testing.T, extractor *mockcontainermetadata.MockCommonContainerMetadataExtractor, cri *mockcri.MockExtendedRuntimeService)
		expectedStartEvent bool
	}{
		{
			name:               "listing sandboxes fails",
			startEventHandler:  newUnitTestStartEventHandler(0, nil),
			wantErr:            true,
			expectedStartEvent: false,
			prepare: func(t *testing.T, extractor *mockcontainermetadata.MockCommonContainerMetadataExtractor, cri *mockcri.MockExtendedRuntimeService) {
				cri.EXPECT().ListPodSandbox(gomock.Eq(listSandboxFilter)).Return(nil, fmt.Errorf("failed")).Times(1)
			},
		},
		{
			name:               "listing sandboxes succeeds, but extracting metadata fails",
			startEventHandler:  newUnitTestStartEventHandler(0, nil),
			wantErr:            false,
			expectedStartEvent: false,
			prepare: func(t *testing.T, extractor *mockcontainermetadata.MockCommonContainerMetadataExtractor, cri *mockcri.MockExtendedRuntimeService) {
				cri.EXPECT().ListPodSandbox(gomock.Eq(listSandboxFilter)).Return(
					[]*runtimeapi.PodSandbox{
						{
							Id: "sandbox-id",
						},
					},
					nil,
				).Times(1)

				ContainerArgs := containermetadata.NewRuncArguments(containermetadata.StartAction, "sandbox-id")
				extractor.EXPECT().Has(gomock.Eq(ContainerArgs)).Return(false).Times(1)
			},
		},
		{
			name:               "listing sandboxes succeeds, sending an event that fails",
			startEventHandler:  newUnitTestStartEventHandler(1, fmt.Errorf("error")),
			wantErr:            false,
			expectedStartEvent: true,
			prepare: func(t *testing.T, extractor *mockcontainermetadata.MockCommonContainerMetadataExtractor, cri *mockcri.MockExtendedRuntimeService) {
				cri.EXPECT().ListPodSandbox(gomock.Eq(listSandboxFilter)).Return(
					[]*runtimeapi.PodSandbox{
						{
							Id: "sandbox-id",
						},
					},
					nil,
				).Times(1)

				ContainerArgs := containermetadata.NewRuncArguments(containermetadata.StartAction, "sandbox-id")
				extractor.EXPECT().Has(gomock.Eq(ContainerArgs)).Return(true).Times(1)
				// technically the first result would need to be populated, but that doesn't matter for the test
				extractor.EXPECT().Extract(gomock.Eq(ContainerArgs)).Return(
					nil,
					mockcontainermetadata.NewMockCommonKubernetesContainerMetadata(nil),
					nil,
				).Times(1)
			},
		},
		{
			name:               "listing 2 sandboxes succeeds, sending 2 start events",
			startEventHandler:  newUnitTestStartEventHandler(2, nil),
			wantErr:            false,
			expectedStartEvent: true,
			prepare: func(t *testing.T, extractor *mockcontainermetadata.MockCommonContainerMetadataExtractor, cri *mockcri.MockExtendedRuntimeService) {
				cri.EXPECT().ListPodSandbox(gomock.Eq(listSandboxFilter)).Return(
					[]*runtimeapi.PodSandbox{
						{
							Id: "sandbox-id-1",
						},
						{
							Id: "sandbox-id-2",
						},
					},
					nil,
				).Times(1)

				ContainerArgs1 := containermetadata.NewRuncArguments(containermetadata.StartAction, "sandbox-id-1")
				extractor.EXPECT().Has(gomock.Eq(ContainerArgs1)).Return(true).Times(1)
				// technically the first result would need to be populated, but that doesn't matter for the test
				extractor.EXPECT().Extract(gomock.Eq(ContainerArgs1)).Return(
					nil,
					mockcontainermetadata.NewMockCommonKubernetesContainerMetadata(nil),
					nil,
				).Times(1)
				ContainerArgs2 := containermetadata.NewRuncArguments(containermetadata.StartAction, "sandbox-id-2")
				extractor.EXPECT().Has(gomock.Eq(ContainerArgs2)).Return(true).Times(1)
				// technically the first result would need to be populated, but that doesn't matter for the test
				extractor.EXPECT().Extract(gomock.Eq(ContainerArgs2)).Return(
					nil,
					mockcontainermetadata.NewMockCommonKubernetesContainerMetadata(nil),
					nil,
				).Times(1)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockExtractor := mockcontainermetadata.NewMockCommonContainerMetadataExtractor(ctrl)
			extractor = mockExtractor
			ctx, cancel := context.WithCancel(context.Background())
			m := New(ctx)
			m.SetupHandlers(&config.ProcessorConfig{
				ResyncLock: &sync.RWMutex{},
			})
			m.SenderReady()
			mockcri := mockcri.NewMockExtendedRuntimeService(ctrl)
			m.criRuntimeService = mockcri
			tt.prepare(t, mockExtractor, mockcri)
			if err := m.onStartup(ctx, tt.startEventHandler.f()); (err != nil) != tt.wantErr {
				t.Errorf("K8sMonitor.onStartup() error = %v, wantErr %v", err, tt.wantErr)
			}
			tt.startEventHandler.wait()
			if tt.expectedStartEvent != tt.startEventHandler.called() {
				t.Errorf("startEventHandler.called() = %v, want %v", tt.startEventHandler.called(), tt.expectedStartEvent)
			}
			cancel()
			ctrl.Finish()
		})
	}
}
