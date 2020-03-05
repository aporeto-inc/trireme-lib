// +build linux !windows

package podmonitor

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"go.aporeto.io/trireme-lib/policy"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func createNewPodMonitor() *PodMonitor {
	m := New()
	mockError := fmt.Errorf("mockerror: overwrite function with your own mock before using")
	monitorConfig := DefaultConfig()
	monitorConfig.Kubeconfig = "testdata/kubeconfig"
	monitorConfig.MetadataExtractor = func(context.Context, client.Client, *runtime.Scheme, *corev1.Pod, bool) (*policy.PURuntime, error) {
		return nil, mockError
	}
	monitorConfig.NetclsProgrammer = func(context.Context, *corev1.Pod, policy.RuntimeReader) error {
		return mockError
	}
	monitorConfig.PidsSetMaxProcsProgrammer = func(ctx context.Context, pod *corev1.Pod, maxProcs int) error {
		return mockError
	}
	monitorConfig.ResetNetcls = func(context.Context) error {
		return mockError
	}
	monitorConfig.SandboxExtractor = func(context.Context, *corev1.Pod) (string, error) {
		return "", mockError
	}

	if err := m.SetupConfig(nil, monitorConfig); err != nil {
		panic(err)
	}
	return m
}

func TestPodMonitor_startManager(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mgr := NewMockManager(ctrl)
	c := NewMockClient(ctrl)
	zc := NewMockCore(ctrl)
	zc.EXPECT().Enabled(zapcore.DebugLevel).AnyTimes().Return(false)

	logger := zap.New(zc)
	zap.ReplaceGlobals(logger)

	ctx := context.Background()
	ctxWithCancel, cancel := context.WithCancel(context.Background())

	type args struct {
		ctx context.Context
		mgr manager.Manager
	}

	m := createNewPodMonitor()
	tests := []struct {
		name           string
		m              *PodMonitor
		args           args
		expect         func(t *testing.T)
		wantErr        bool
		wantKubeClient bool
	}{
		{
			name: "successful startup",
			m:    m,
			args: args{
				ctx: ctx,
				mgr: mgr,
			},
			wantErr:        false,
			wantKubeClient: true,
			expect: func(t *testing.T) {
				var r manager.Runnable
				mgr.EXPECT().Add(gomock.Any()).DoAndReturn(func(run manager.Runnable) error {
					r = run
					return nil
				}).Times(1)
				mgr.EXPECT().Start(gomock.Any()).DoAndReturn(func(z <-chan struct{}) error {
					go r.Start(z) //nolint
					return nil
				}).Times(1)
				mgr.EXPECT().GetClient().Times(1).Return(c)
			},
		},
		{
			name: "successful startup after 6s must write warning log",
			m:    m,
			args: args{
				ctx: ctx,
				mgr: mgr,
			},
			wantErr:        false,
			wantKubeClient: true,
			expect: func(t *testing.T) {
				zc.EXPECT().Enabled(zapcore.WarnLevel).Times(1).Return(true)
				zc.EXPECT().Check(gomock.Any(), gomock.Any()).Times(1).DoAndReturn(func(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
					return ce.AddCore(ent, zc)
				})
				zc.EXPECT().Write(gomock.Any(), gomock.Any()).Times(1).DoAndReturn(func(ent zapcore.Entry, fields []zapcore.Field) error {
					expectedLogMessage := startupWarningMessage
					if ent.Message != expectedLogMessage {
						t.Errorf("expectedLogMessage = '%s', ent.Message = '%s'", expectedLogMessage, ent.Message)
					}
					return nil
				})
				var r manager.Runnable
				mgr.EXPECT().Add(gomock.Any()).DoAndReturn(func(run manager.Runnable) error {
					r = run
					return nil
				}).Times(1)
				mgr.EXPECT().Start(gomock.Any()).DoAndReturn(func(z <-chan struct{}) error {
					go func() {
						time.Sleep(6 * time.Second)
						r.Start(z) //nolint
					}()
					return nil
				}).Times(1)
				mgr.EXPECT().GetClient().Times(1).Return(c)
			},
		},
		{
			name: "adding controller fails",
			m:    m,
			args: args{
				ctx: ctx,
				mgr: mgr,
			},
			wantErr: true,
			expect: func(t *testing.T) {
				mgr.EXPECT().Add(gomock.Any()).Return(fmt.Errorf("error")).Times(1)
			},
		},
		{
			name: "starting controller fails",
			m:    m,
			args: args{
				ctx: ctx,
				mgr: mgr,
			},
			wantErr: true,
			expect: func(t *testing.T) {
				mgr.EXPECT().Add(gomock.Any()).Return(nil).Times(1)
				mgr.EXPECT().Start(gomock.Any()).Return(fmt.Errorf("error")).Times(1)
			},
		},
		{
			name: "context is being cancelled cancelled",
			m:    m,
			args: args{
				ctx: ctxWithCancel,
				mgr: mgr,
			},
			wantErr: true,
			expect: func(t *testing.T) {
				mgr.EXPECT().Add(gomock.Any()).Return(nil).Times(1)
				mgr.EXPECT().Start(gomock.Any()).DoAndReturn(func(z <-chan struct{}) error {
					cancel()
					return nil
				}).Times(1)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.expect(t)
			tt.m.kubeClient = nil
			if err := tt.m.startManager(tt.args.ctx, tt.args.mgr); (err != nil) != tt.wantErr {
				t.Errorf("PodMonitor.startManager() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantKubeClient && tt.m.kubeClient == nil {
				t.Errorf("PodMonitor.startManager() kubeClient = %v, wantKubeClient %v", tt.m.kubeClient, tt.wantKubeClient)
			}
			if !tt.wantKubeClient && tt.m.kubeClient != nil {
				t.Errorf("PodMonitor.startManager() kubeClient = %v, wantKubeClient %v", tt.m.kubeClient, tt.wantKubeClient)
			}
		})
	}
}
