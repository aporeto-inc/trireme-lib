// +build linux !windows

package podmonitor

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/policy/mockpolicy"
	"go.uber.org/zap"
	zapcore "go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	cache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/runtime/inject"
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

func isKubernetesController() gomock.Matcher {
	return &controllerMatcher{}
}

type controllerMatcher struct{}

var _ gomock.Matcher = &controllerMatcher{}

// Matches returns whether x is a match.
func (m *controllerMatcher) Matches(x interface{}) bool {
	_, ok := x.(controller.Controller)
	return ok
}

// String describes what the matcher matches.
func (m *controllerMatcher) String() string {
	return "is not a Kubernetes controller"
}

func TestPodMonitor_startManager(t *testing.T) {

	// overwrite globals
	retrySleep = time.Millisecond * 10
	//warningMessageSleep = time.Millisecond * 300
	warningTimeout = time.Millisecond * 300

	// use this like:
	//   managerNew = managerNewTest(mgr, nil)
	managerNewTest := func(mgr *MockManager, err error) func(*rest.Config, manager.Options) (manager.Manager, error) {
		return func(*rest.Config, manager.Options) (manager.Manager, error) {
			return mgr, err
		}
	}

	m := createNewPodMonitor()

	tests := []struct {
		name           string
		m              *PodMonitor
		expect         func(*testing.T, *gomock.Controller, context.Context, context.CancelFunc)
		wantKubeClient bool
	}{
		{
			name:           "successful startup without any errors in the expected timeframe",
			m:              m,
			wantKubeClient: true,
			expect: func(t *testing.T, ctrl *gomock.Controller, ctx context.Context, cancel context.CancelFunc) {
				mgr := NewMockManager(ctrl)
				managerNew = managerNewTest(mgr, nil)
				c := NewMockClient(ctrl)
				cch := NewMockCache(ctrl)
				inf := NewMockSharedIndexInformer(ctrl)

				// this is our version of a mocked SetFields function
				var sf func(i interface{}) error
				sf = func(i interface{}) error {
					if _, err := inject.InjectorInto(sf, i); err != nil {
						return err
					}
					if _, err := inject.SchemeInto(scheme.Scheme, i); err != nil {
						return err
					}
					if _, err := inject.CacheInto(cch, i); err != nil {
						return err
					}
					if _, err := inject.StopChannelInto(ctx.Done(), i); err != nil {
						return err
					}
					return nil
				}

				// delete controller
				mgr.EXPECT().Add(gomock.AssignableToTypeOf(&DeleteController{})).Times(1).Return(nil)
				mgr.EXPECT().GetClient().Times(1).Return(c)

				// main controller
				// newReconciler calls these
				mgr.EXPECT().GetClient().Times(1).Return(c)
				mgr.EXPECT().GetScheme().Times(1).Return(scheme.Scheme)
				mgr.EXPECT().GetRecorder("trireme-pod-controller").Times(1).Return(nil)
				// addController calls controller.New which calls these
				mgr.EXPECT().SetFields(gomock.AssignableToTypeOf(&ReconcilePod{})).Times(1).DoAndReturn(sf)
				mgr.EXPECT().GetCache().Times(1).Return(cch)
				mgr.EXPECT().GetConfig().Times(1).Return(nil)
				mgr.EXPECT().GetScheme().Times(1).Return(scheme.Scheme)
				mgr.EXPECT().GetClient().Times(2).Return(c) // once inside of controller.New and once by us
				mgr.EXPECT().GetRecorder("trireme-pod-controller").Times(1).Return(nil)
				mgr.EXPECT().Add(isKubernetesController()).Times(1).DoAndReturn(func(run manager.Runnable) error {
					return sf(run)
				})
				// these are called by our c.Watch statement for registering our Pod event source
				// NOTE: this will also call Start on the informer already! This is the reason why the mgr.Start which
				//       waits for the caches to be filled will already download a fresh list of all the pods!
				cch.EXPECT().GetInformer(gomock.AssignableToTypeOf(&corev1.Pod{})).Times(1).DoAndReturn(func(arg0 runtime.Object) (cache.SharedIndexInformer, error) {
					return inf, nil
				})
				inf.EXPECT().AddEventHandler(gomock.Any()).Times(1)

				// monitoring/side controller
				var r manager.Runnable
				mgr.EXPECT().Add(gomock.AssignableToTypeOf(&runnable{})).DoAndReturn(func(run manager.Runnable) error {
					r = run
					return nil
				}).Times(1)

				// the manager start needs to at least start the monitoring controller for the right behaviour in our code
				mgr.EXPECT().Start(gomock.Any()).DoAndReturn(func(z <-chan struct{}) error {
					go r.Start(z) //nolint
					return nil
				}).Times(1)

				// after start, we call GetClient as well to assign it to the monitor
				mgr.EXPECT().GetClient().Times(1).Return(c)

				// on successful startup, we only expect one debug message at the end
				// we setup everything here to ensure that *only* this log will appear
				// we are additionally testing if the logic of the if condition worked
				zc := NewMockCore(ctrl)
				logger := zap.New(zc)
				zap.ReplaceGlobals(logger)
				zc.EXPECT().Enabled(zapcore.DebugLevel).Times(1).Return(true)
				zc.EXPECT().Check(gomock.Any(), gomock.Any()).Times(1).DoAndReturn(func(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
					return ce.AddCore(ent, zc)
				})
				zc.EXPECT().Write(gomock.Any(), gomock.Any()).Times(1).DoAndReturn(func(ent zapcore.Entry, fields []zapcore.Field) error {
					expectedLogMessage := "pod: controller startup finished"
					if !strings.HasPrefix(ent.Message, expectedLogMessage) {
						t.Errorf("expectedLogMessage = '%s', ent.Message = '%s'", expectedLogMessage, ent.Message)
						return nil
					}
					var foundDuration bool
					for _, field := range fields {
						if field.Key == "duration" {
							foundDuration = true
							if field.Type != zapcore.DurationType {
								t.Errorf("duration field of log message is not DurationType (8), but %v", field.Type)
								break
							}
							d := time.Duration(field.Integer)
							if d > warningTimeout {
								t.Errorf("startup time (%s), surpassed the warningTimeout (%s), but printed it as debug log instead of warning", d, warningTimeout)
							}
							break
						}
					}
					if !foundDuration {
						t.Errorf("did not find debug log message which has test duration field")
					}
					return nil
				})
			},
		},
		/*{
			name: "successful startup after 6s must write warning log",
			m:    m,
			args: args{
				ctx: ctx,
			},
			wantKubeClient: true,
			expect: func(t *testing.T, ctrl *gomock.Controller) {
				mgr := NewMockManager(ctrl)
				managerNew = managerNewTest(mgr, nil)
				c := NewMockClient(ctrl)
				zc := NewMockCore(ctrl)
				zc.EXPECT().Enabled(zapcore.DebugLevel).AnyTimes().Return(false)
				logger := zap.New(zc)
				zap.ReplaceGlobals(logger)

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
			},
			expect: func(t *testing.T, ctrl *gomock.Controller) {
				mgr := NewMockManager(ctrl)
				managerNew = managerNewTest(mgr, nil)
				mgr.EXPECT().Add(gomock.Any()).Return(fmt.Errorf("error")).Times(1)
			},
		},
		{
			name: "starting controller fails",
			m:    m,
			args: args{
				ctx: ctx,
			},
			expect: func(t *testing.T, ctrl *gomock.Controller) {
				mgr := NewMockManager(ctrl)
				managerNew = managerNewTest(mgr, nil)
				mgr.EXPECT().Add(gomock.Any()).Return(nil).Times(1)
				mgr.EXPECT().Start(gomock.Any()).Return(fmt.Errorf("error")).Times(1)
			},
		},
		{
			name: "context is being cancelled",
			m:    m,
			args: args{
				ctx:    ctxWithCancel,
				cancel: cancel,
			},
			expect: func(t *testing.T, ctrl *gomock.Controller) {
				mgr := NewMockManager(ctrl)
				managerNew = managerNewTest(mgr, nil)
				mgr.EXPECT().Add(gomock.Any()).Return(nil).Times(1)
				mgr.EXPECT().Start(gomock.Any()).DoAndReturn(func(z <-chan struct{}) error {
					cancel()
					return nil
				}).Times(1)
			},
		},*/
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// create a mock controller per test run to track mocked calls
			// call expect to register and prepare for the side effects of the functions
			// always nil the kubeClient for every call
			ctx, cancel := context.WithCancel(context.Background())
			ctrl := gomock.NewController(t)
			tt.expect(t, ctrl, ctx, cancel)
			tt.m.kubeClient = nil

			// probably paranoid: this ensures that nothing in the tested function actually calls out to the policy engine yet
			handler := mockpolicy.NewMockResolver(ctrl)
			pc := &config.ProcessorConfig{
				Policy: handler,
			}
			tt.m.SetupHandlers(pc)

			// now execute the mocked test
			tt.m.startManager(ctx)

			// do the kubeclient check
			if tt.wantKubeClient && tt.m.kubeClient == nil {
				t.Errorf("PodMonitor.startManager() kubeClient = %v, wantKubeClient %v", tt.m.kubeClient, tt.wantKubeClient)
			}
			if !tt.wantKubeClient && tt.m.kubeClient != nil {
				t.Errorf("PodMonitor.startManager() kubeClient = %v, wantKubeClient %v", tt.m.kubeClient, tt.wantKubeClient)
			}

			// call Finish on every test run to ensure the calls add up per test
			// this is essentially the real check of all the test conditions as the whole function is side-effecting only
			ctrl.Finish()
			cancel()
		})
	}
}

func TestPodMonitor_Resync(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()

	c := NewMockClient(ctrl)
	m := createNewPodMonitor()
	handler := mockpolicy.NewMockResolver(ctrl)
	pc := &config.ProcessorConfig{
		Policy: handler,
	}
	m.SetupHandlers(pc)

	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		m       *PodMonitor
		expect  func(t *testing.T, m *PodMonitor)
		args    args
		wantErr bool
	}{
		{
			name: "resync fails with a failing reset netcls",
			m:    m,
			args: args{
				ctx: ctx,
			},
			expect: func(t *testing.T, m *PodMonitor) {
				m.kubeClient = c
				m.resetNetcls = func(context.Context) error {
					return fmt.Errorf("resync error")
				}
			},
			wantErr: true,
		},
		{
			name: "resync fails with a missing kubeclient",
			m:    m,
			args: args{
				ctx: ctx,
			},
			expect: func(t *testing.T, m *PodMonitor) {
				m.kubeClient = nil
				m.resetNetcls = func(context.Context) error {
					return nil
				}
			},
			wantErr: true,
		},
		{
			name: "successful call to ResyncWathAllPods",
			m:    m,
			args: args{
				ctx: ctx,
			},
			expect: func(t *testing.T, m *PodMonitor) {
				m.kubeClient = c
				m.resetNetcls = func(context.Context) error {
					return nil
				}
				c.EXPECT().List(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(nil)
			},
			wantErr: false,
		},
		// not more to test, the heavy lifting is done in ResyncWithAllPods
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.expect(t, tt.m)
			if err := tt.m.Resync(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("PodMonitor.Resync() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
