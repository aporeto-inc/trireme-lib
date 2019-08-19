package podmonitor

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.aporeto.io/trireme-lib/monitor/extractors"

	"go.aporeto.io/trireme-lib/common"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/policy/mockpolicy"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// TODO: should be a mock, but how to create it? we don't even vendor in tireme-lib
type fakeRecorder struct{}

func (r *fakeRecorder) Event(object runtime.Object, eventtype, reason, message string) {
}
func (r *fakeRecorder) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...interface{}) {
}
func (r *fakeRecorder) PastEventf(object runtime.Object, timestamp metav1.Time, eventtype, reason, messageFmt string, args ...interface{}) {
}
func (r *fakeRecorder) AnnotatedEventf(object runtime.Object, annotations map[string]string, eventtype, reason, messageFmt string, args ...interface{}) {
}

func TestController(t *testing.T) {
	Convey("Given a reconciler", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		// ctx := context.TODO()

		failure := fmt.Errorf("fail hard")

		pod1 := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod1",
				Namespace: "default",
				UID:       types.UID("default/pod1"),
			},
		}
		pod2 := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod2",
				Namespace: "default",
				UID:       types.UID("default/pod2"),
			},
			Spec: corev1.PodSpec{
				HostNetwork: true,
			},
		}
		pod3 := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "pod3",
				Namespace:         "default",
				UID:               types.UID("default/pod3"),
				DeletionTimestamp: &metav1.Time{Time: time.Now()},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
			},
		}
		podUnknown := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "unknown",
				Namespace: "default",
				UID:       types.UID("default/unknown"),
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodUnknown,
			},
		}
		podUnrecognized := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "unrecognized",
				Namespace: "default",
				UID:       types.UID("default/unrecognized"),
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodPhase("not-really-a-pod-phase"),
			},
		}
		podFailed := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "failed",
				Namespace: "default",
				UID:       types.UID("default/failed"),
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodFailed,
			},
		}
		podSucceeded := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "succeeded",
				Namespace: "default",
				UID:       types.UID("default/succeeded"),
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodSucceeded,
			},
		}
		podPending := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pending",
				Namespace: "default",
				UID:       types.UID("default/pending"),
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodPending,
			},
		}
		podPendingAndStarted := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pendingAndStarted",
				Namespace: "default",
				UID:       types.UID("default/pendingAndStarted"),
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodPending,
				InitContainerStatuses: []corev1.ContainerStatus{
					{
						State: corev1.ContainerState{
							Running: &corev1.ContainerStateRunning{
								StartedAt: metav1.Time{Time: time.Now()},
							},
						},
					},
				},
			},
		}
		podRunningNotStarted := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "runningNotStarted",
				Namespace: "default",
				UID:       types.UID("default/runningNotStarted"),
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
			},
		}
		podRunning := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "running",
				Namespace: "default",
				UID:       types.UID("default/running"),
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				InitContainerStatuses: []corev1.ContainerStatus{
					{
						State: corev1.ContainerState{
							Terminated: &corev1.ContainerStateTerminated{
								ExitCode: 0,
							},
						},
					},
				},
				ContainerStatuses: []corev1.ContainerStatus{
					{
						State: corev1.ContainerState{
							Running: &corev1.ContainerStateRunning{
								StartedAt: metav1.Time{Time: time.Now()},
							},
						},
					},
				},
			},
		}
		podRunningHostNetwork := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "runningHostNetwork",
				Namespace: "default",
				UID:       types.UID("default/runningHostNetwork"),
			},
			Spec: corev1.PodSpec{
				HostNetwork: true,
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{
					{
						State: corev1.ContainerState{
							Running: &corev1.ContainerStateRunning{
								StartedAt: metav1.Time{Time: time.Now()},
							},
						},
					},
				},
			},
		}
		c := fakeclient.NewFakeClient(pod1, pod2, pod3, podUnknown, podUnrecognized, podSucceeded, podFailed, podPending, podPendingAndStarted, podRunningNotStarted, podRunning, podRunningHostNetwork)

		handler := mockpolicy.NewMockResolver(ctrl)

		metadataExtractor := func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
			return nil, nil
		}
		netclsProgrammer := func(context.Context, *corev1.Pod, policy.RuntimeReader) error {
			return nil
		}
		sandboxExtractor := func(context.Context, *corev1.Pod) (string, error) {
			return "", nil
		}
		// we will only send all delete events in this test, we are not going to handle them
		deleteCh := make(chan DeleteEvent, 1000)
		deleteReconcileCh := make(chan struct{}, 1000)

		pc := &config.ProcessorConfig{
			Policy: handler,
		}

		r := &ReconcilePod{
			client:            c,
			scheme:            scheme.Scheme,
			recorder:          &fakeRecorder{},
			handler:           pc,
			metadataExtractor: metadataExtractor,
			netclsProgrammer:  netclsProgrammer,
			sandboxExtractor:  sandboxExtractor,
			nodeName:          "testing-node",
			enableHostPods:    true,
			deleteCh:          deleteCh,
			deleteReconcileCh: deleteReconcileCh,

			// taken from original file
			handlePUEventTimeout:   5 * time.Second,
			metadataExtractTimeout: 3 * time.Second,
			netclsProgramTimeout:   2 * time.Second,
		}

		Convey("a not existing pod should trigger a destroy event without any error", func() {
			//handler.EXPECT().HandlePUEvent(gomock.Any(), "b/a", common.EventDestroy, gomock.Any()).Return(nil).Times(1)
			_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "a", Namespace: "b"}})
			So(err, ShouldBeNil)
		})

		Convey("a not existing pod should trigger a destroy event, and *not* fail if it cannot handle the destroy", func() {
			//handler.EXPECT().HandlePUEvent(gomock.Any(), "b/a", common.EventDestroy, gomock.Any()).Return(fmt.Errorf("stopping failed")).Times(1)
			_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "a", Namespace: "b"}})
			So(err, ShouldBeNil)
		})

		Convey("an existing pod with HostNetwork=true, but host pod activation disabled, should silently return", func() {
			r.enableHostPods = false
			_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "pod2", Namespace: "default"}})
			So(err, ShouldBeNil)
		})

		Convey("a pod which is terminating, should update metadata and silently return", func() {
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/pod3", common.EventUpdate, gomock.Any()).Return(nil).Times(1)
			_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "pod3", Namespace: "default"}})
			So(err, ShouldBeNil)
		})

		Convey("a pod which is in PodUnknown state should silently return", func() {
			_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "unknown", Namespace: "default"}})
			So(err, ShouldBeNil)
		})

		Convey("a pod which has an unrecognized pod phase should silently return", func() {
			_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "unrecognized", Namespace: "default"}})
			So(err, ShouldBeNil)
		})

		Convey("a pod which is in podsucceeded or podfailed state should try to stop the PU", func() {
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/failed", common.EventUpdate, gomock.Any()).Return(fmt.Errorf("update failed")).Times(1)
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/failed", common.EventStop, gomock.Any()).Return(fmt.Errorf("stop failed")).Times(1)
			_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "failed", Namespace: "default"}})
			So(err, ShouldBeNil)

			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/succeeded", common.EventUpdate, gomock.Any()).Return(nil).Times(1)
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/succeeded", common.EventStop, gomock.Any()).Return(nil).Times(1)
			_, err = r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "succeeded", Namespace: "default"}})
			So(err, ShouldBeNil)

			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/succeeded", common.EventUpdate, gomock.Any()).Return(policy.ErrPUNotFound("default/succeeded", nil)).Times(1)
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/succeeded", common.EventStop, gomock.Any()).Return(policy.ErrPUNotFound("default/succeeded", nil)).Times(1)
			_, err = r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "succeeded", Namespace: "default"}})
			So(err, ShouldBeNil)

			Convey("and retry if metadata extraction fails", func() {
				r.metadataExtractor = func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
					return nil, failure
				}
				_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "succeeded", Namespace: "default"}})
				So(err, ShouldNotBeNil)
				So(err, ShouldEqual, failure)
			})

			Reset(func() {
				r.metadataExtractor = metadataExtractor
			})
		})

		Convey("a pod in pending state should update or create a PU if it does already exist", func() {
			// metadata extractor needs to change tags in order to provoke an update call
			r.metadataExtractor = func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
				ru := policy.NewPURuntimeWithDefaults()
				ru.SetTags(policy.NewTagStoreFromMap(map[string]string{"exists": "exists", "a": "b"}))
				return ru, nil
			}

			// update works
			existingRuntime := policy.NewPURuntimeWithDefaults()
			existingRuntime.SetTags(policy.NewTagStoreFromMap(map[string]string{"exists": "exists"}))
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/pending", common.EventUpdate, gomock.Any()).Return(nil).Times(1)
			_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "pending", Namespace: "default"}})
			So(err, ShouldBeNil)

			// update fails hard
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/pending", common.EventUpdate, gomock.Any()).Return(failure).Times(1)
			_, err = r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "pending", Namespace: "default"}})
			So(err, ShouldBeNil)

			// PU does not exist, but create fails hard
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/pending", common.EventUpdate, gomock.Any()).Return(policy.ErrPUNotFound("default/pending", nil)).Times(1)
			_, err = r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "pending", Namespace: "default"}})
			So(err, ShouldBeNil)

			// PU does not exist, but create succeeds
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/pending", common.EventUpdate, gomock.Any()).Return(policy.ErrPUNotFound("default/pending", nil)).Times(1)
			_, err = r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "pending", Namespace: "default"}})
			So(err, ShouldBeNil)
		})

		Convey("a pod in pending state which has an init container started, should silently return if everything could be started", func() {
			r.metadataExtractor = func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
				return policy.NewPURuntime("default/pendingAndStarted", 42, "", nil, nil, common.ContainerPU, nil), nil
			}
			r.sandboxExtractor = func(context.Context, *corev1.Pod) (string, error) {
				return "test", nil
			}
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/pendingAndStarted", common.EventUpdate, gomock.Any()).Return(nil).Times(1)
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/pendingAndStarted", common.EventStart, gomock.Any()).Return(nil).Times(1)
			_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "pendingAndStarted", Namespace: "default"}})
			So(err, ShouldBeNil)
		})

		Convey("a pod in running state should silently return if no containers have been started yet", func() {
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/runningNotStarted", common.EventUpdate, gomock.Any()).Return(nil).Times(1)
			_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "runningNotStarted", Namespace: "default"}})
			So(err, ShouldBeNil)
		})

		Convey("a pod in running state", func() {
			Convey("should retry if metadata extraction fails", func() {
				r.metadataExtractor = func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
					return nil, failure
				}
				_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "running", Namespace: "default"}})
				So(err, ShouldNotBeNil)
				So(err, ShouldEqual, failure)
			})
			Convey("should retry if metadata extraction succeeded, but no PID nor netns path were found and this is not a hostnetwork pod", func() {
				handler.EXPECT().HandlePUEvent(gomock.Any(), "default/running", common.EventUpdate, gomock.Any()).Return(nil).Times(1)
				r.metadataExtractor = func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
					return policy.NewPURuntimeWithDefaults(), nil
				}
				r.sandboxExtractor = func(context.Context, *corev1.Pod) (string, error) {
					return "test", nil
				}
				_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "running", Namespace: "default"}})
				So(err, ShouldNotBeNil)
				So(err, ShouldEqual, ErrNetnsExtractionMissing)
			})
			Convey("should *not* fail if metadata and PID/netnspath extraction succeeded, but the Start PU event fails", func() {
				r.metadataExtractor = func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
					return policy.NewPURuntime("default/running", 42, "", nil, nil, common.ContainerPU, nil), nil
				}
				r.sandboxExtractor = func(context.Context, *corev1.Pod) (string, error) {
					return "test", nil
				}
				handler.EXPECT().HandlePUEvent(gomock.Any(), "default/running", common.EventUpdate, gomock.Any()).Return(nil).Times(1)
				handler.EXPECT().HandlePUEvent(gomock.Any(), "default/running", common.EventStart, gomock.Any()).Return(failure).Times(1)
				_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "running", Namespace: "default"}})
				So(err, ShouldBeNil)
			})
			Convey("should return silently if metadata and PID/netnspath extraction succeeded, but the PU has already been activated", func() {
				r.metadataExtractor = func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
					return policy.NewPURuntime("default/running", 42, "", nil, nil, common.ContainerPU, nil), nil
				}
				r.sandboxExtractor = func(context.Context, *corev1.Pod) (string, error) {
					return "test", nil
				}
				handler.EXPECT().HandlePUEvent(gomock.Any(), "default/running", common.EventUpdate, gomock.Any()).Return(nil).Times(1)
				handler.EXPECT().HandlePUEvent(gomock.Any(), "default/running", common.EventStart, gomock.Any()).Return(policy.ErrPUAlreadyActivated("default/running", nil)).Times(1)
				_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "running", Namespace: "default"}})
				So(err, ShouldBeNil)
			})
			Convey("should return silently if metadata and PID/netnspath extraction succeeded, and the PU could be successfully activated", func() {
				r.metadataExtractor = func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
					return policy.NewPURuntime("default/running", 42, "", nil, nil, common.ContainerPU, nil), nil
				}
				r.sandboxExtractor = func(context.Context, *corev1.Pod) (string, error) {
					return "test", nil
				}
				handler.EXPECT().HandlePUEvent(gomock.Any(), "default/running", common.EventUpdate, gomock.Any()).Return(nil).Times(1)
				handler.EXPECT().HandlePUEvent(gomock.Any(), "default/running", common.EventStart, gomock.Any()).Return(nil).Times(1)
				_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "running", Namespace: "default"}})
				So(err, ShouldBeNil)
			})
		})

		Convey("a HostNetwork=true pod should try to start the PU and try to program the netcls cgroup", func() {
			r.metadataExtractor = func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
				return policy.NewPURuntime("default/runningHostNetwork", 0, "", nil, nil, common.LinuxProcessPU, nil), nil
			}
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/runningHostNetwork", common.EventUpdate, gomock.Any()).Return(nil).Times(1)
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/runningHostNetwork", common.EventStart, gomock.Any()).Return(nil).AnyTimes()
			Convey("and succeed if metadata extraction succeeded, and netcls cgroup programming succeeded", func() {
				_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "runningHostNetwork", Namespace: "default"}})
				So(err, ShouldBeNil)
			})
			Convey("and succeed if metadata extraction succeeded, and netcls cgroup programming failed with netcls already programmed", func() {
				r.netclsProgrammer = func(context.Context, *corev1.Pod, policy.RuntimeReader) error {
					return extractors.ErrNetclsAlreadyProgrammed("mark")
				}
				_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "runningHostNetwork", Namespace: "default"}})
				So(err, ShouldBeNil)
			})
			Convey("and return silently if metadata extraction succeeded, but netcls cgroup programming discovered that this pod is not a host network pod (cannot recover)", func() {
				r.netclsProgrammer = func(context.Context, *corev1.Pod, policy.RuntimeReader) error {
					return extractors.ErrNoHostNetworkPod
				}
				_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "runningHostNetwork", Namespace: "default"}})
				So(err, ShouldBeNil)
			})
			Convey("should fail if metadata extraction succeeded, but netcls cgroup programming fails", func() {
				r.netclsProgrammer = func(context.Context, *corev1.Pod, policy.RuntimeReader) error {
					return failure
				}
				r.sandboxExtractor = func(context.Context, *corev1.Pod) (string, error) {
					return "test", nil
				}
				_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "runningHostNetwork", Namespace: "default"}})
				So(err, ShouldNotBeNil)
				So(err, ShouldEqual, failure)
			})
		})
	})
}
