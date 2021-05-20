package k8smonitor

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"go.aporeto.io/enforcerd/internal/extractors/containermetadata"
	"go.aporeto.io/enforcerd/internal/extractors/containermetadata/mockcontainermetadata"
)

func Test_calculateWaitTime(t *testing.T) {
	tests := []struct {
		name  string
		retry uint
		want  time.Duration
	}{
		{
			retry: 0,
			want:  0,
		},
		{
			retry: 1,
			want:  retryWaittimeUnit * time.Duration(1),
		},
		{
			retry: 2,
			want:  retryWaittimeUnit * time.Duration(1),
		},
		{
			retry: 3,
			want:  retryWaittimeUnit * time.Duration(2),
		},
		{
			retry: 4,
			want:  retryWaittimeUnit * time.Duration(3),
		},
		{
			retry: 5,
			want:  retryWaittimeUnit * time.Duration(5),
		},
		{
			retry: 6,
			want:  retryWaittimeUnit * time.Duration(8),
		},
		{
			retry: 7,
			want:  retryWaittimeUnit * time.Duration(13),
		},
		{
			retry: 8,
			want:  retryWaittimeUnit * time.Duration(21),
		},
		{
			retry: 9,
			want:  retryWaittimeUnit * time.Duration(34),
		},
		{
			retry: 10,
			want:  retryWaittimeUnit * time.Duration(55),
		},
		{
			retry: 1000000,
			want:  retryWaittimeUnit * time.Duration(55),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := calculateWaitTime(tt.retry); got != tt.want {
				t.Errorf("calculateWaitTime() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newStartEventRetryFunc(t *testing.T) {
	oldRetryWaittimeUnit := retryWaittimeUnit
	defer func() {
		retryWaittimeUnit = oldRetryWaittimeUnit
	}()
	retryWaittimeUnit = 0

	// used by the test which needs a cancelled context
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name               string
		mainCtx            context.Context
		startEventHandler  unitTestStartEvent
		retry              uint
		prepare            func(t *testing.T, extractor *mockcontainermetadata.MockCommonContainerMetadataExtractor, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata)
		expectedStartEvent bool
	}{
		{
			name:              "not a pod sandbox",
			mainCtx:           context.Background(),
			startEventHandler: newUnitTestStartEventHandler(0, nil),
			prepare: func(t *testing.T, extractor *mockcontainermetadata.MockCommonContainerMetadataExtractor, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodContainer).Times(2)
				kmd.EXPECT().ID().Return("containerID").Times(1)
			},
		},
		{
			name:              "main context is already cancelled",
			mainCtx:           cancelledCtx,
			startEventHandler: newUnitTestStartEventHandler(0, nil),
			prepare: func(t *testing.T, extractor *mockcontainermetadata.MockCommonContainerMetadataExtractor, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodSandbox).Times(1)
				kmd.EXPECT().ID().Return("containerID").Times(1)
			},
		},
		{
			name:              "sandbox does not exist any longer",
			mainCtx:           context.Background(),
			startEventHandler: newUnitTestStartEventHandler(0, nil),
			prepare: func(t *testing.T, extractor *mockcontainermetadata.MockCommonContainerMetadataExtractor, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodSandbox).Times(1)
				kmd.EXPECT().ID().Return("containerID").Times(3)
				extractor.EXPECT().Has(gomock.Eq(containermetadata.NewRuncArguments(containermetadata.StartAction, "containerID"))).Return(false).Times(1)
			},
		},
		{
			name:              "retrying with success",
			mainCtx:           context.Background(),
			startEventHandler: newUnitTestStartEventHandler(1, nil),
			prepare: func(t *testing.T, extractor *mockcontainermetadata.MockCommonContainerMetadataExtractor, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodSandbox).Times(1)
				kmd.EXPECT().ID().Return("containerID").Times(2)
				extractor.EXPECT().Has(gomock.Eq(containermetadata.NewRuncArguments(containermetadata.StartAction, "containerID"))).Return(true).Times(1)
			},
			expectedStartEvent: true,
		},
		{
			name:              "retrying with error",
			mainCtx:           context.Background(),
			startEventHandler: newUnitTestStartEventHandler(1, fmt.Errorf("start event failed")),
			prepare: func(t *testing.T, extractor *mockcontainermetadata.MockCommonContainerMetadataExtractor, kmd *mockcontainermetadata.MockCommonKubernetesContainerMetadata) {
				kmd.EXPECT().Kind().Return(containermetadata.PodSandbox).Times(1)
				kmd.EXPECT().ID().Return("containerID").Times(3)
				kmd.EXPECT().PodName().Return("podName").Times(1)
				kmd.EXPECT().PodNamespace().Return("podNamespace").Times(1)
				kmd.EXPECT().PodUID().Return("podUID").Times(1)
				extractor.EXPECT().Has(gomock.Eq(containermetadata.NewRuncArguments(containermetadata.StartAction, "containerID"))).Return(true).Times(1)
			},
			expectedStartEvent: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			extractor := mockcontainermetadata.NewMockCommonContainerMetadataExtractor(ctrl)
			kmd := mockcontainermetadata.NewMockCommonKubernetesContainerMetadata(ctrl)
			ctx, cancel := context.WithCancel(tt.mainCtx)
			startEventRetry := newStartEventRetryFunc(ctx, extractor, tt.startEventHandler.f())
			tt.prepare(t, extractor, kmd)
			startEventRetry(kmd, tt.retry)
			tt.startEventHandler.wait()
			if tt.expectedStartEvent != tt.startEventHandler.called() {
				t.Errorf("startEventHandler.called() = %v, want %v", tt.startEventHandler.called(), tt.expectedStartEvent)
			}
			cancel()
			ctrl.Finish()
		})
	}
}
