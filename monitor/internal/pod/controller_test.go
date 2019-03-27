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
			},
		}
		pod2 := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod2",
				Namespace: "default",
			},
			Spec: corev1.PodSpec{
				HostNetwork: true,
			},
		}
		pod3 := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "pod3",
				Namespace:         "default",
				DeletionTimestamp: &metav1.Time{Time: time.Now()},
			},
		}
		podUnknown := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "unknown",
				Namespace: "default",
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodUnknown,
			},
		}
		podUnrecognized := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "unrecognized",
				Namespace: "default",
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodPhase("not-really-a-pod-phase"),
			},
		}
		podFailed := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "failed",
				Namespace: "default",
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodFailed,
			},
		}
		podSucceeded := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "succeeded",
				Namespace: "default",
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodSucceeded,
			},
		}
		podPending := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pending",
				Namespace: "default",
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodPending,
			},
		}
		podRunningNotStarted := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "runningNotStarted",
				Namespace: "default",
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
			},
		}
		podRunning := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "running",
				Namespace: "default",
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
		c := fakeclient.NewFakeClient(pod1, pod2, pod3, podUnknown, podUnrecognized, podSucceeded, podFailed, podPending, podRunningNotStarted, podRunning, podRunningHostNetwork)

		handler := mockpolicy.NewMockResolver(ctrl)

		metadataExtractor := func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
			return nil, nil
		}
		metadataExtractorFailure := func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
			return nil, fmt.Errorf("metadata extraction failed")
		}
		netclsProgrammer := func(context.Context, *corev1.Pod, policy.RuntimeReader) error {
			return nil
		}

		r := &ReconcilePod{
			client:   c,
			scheme:   scheme.Scheme,
			recorder: &fakeRecorder{},
			handler: &config.ProcessorConfig{
				Policy: handler,
			},
			metadataExtractor: metadataExtractor,
			netclsProgrammer:  netclsProgrammer,
			nodeName:          "testing-node",
			enableHostPods:    true,

			// taken from original file
			handlePUEventTimeout:   5 * time.Second,
			metadataExtractTimeout: 3 * time.Second,
			netclsProgramTimeout:   2 * time.Second,
		}

		Convey("a not existing pod should trigger a stop (even a failing one) and destroy event without any error", func() {
			handler.EXPECT().HandlePUEvent(gomock.Any(), "b/a", common.EventStop, gomock.Any()).Return(fmt.Errorf("stopping failed")).Times(1)
			handler.EXPECT().HandlePUEvent(gomock.Any(), "b/a", common.EventDestroy, gomock.Any()).Return(nil).Times(1)
			_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "a", Namespace: "b"}})
			So(err, ShouldBeNil)
		})

		Convey("a not existing pod should trigger a stop and destroy event, and fail if it cannot handle the destroy", func() {
			handler.EXPECT().HandlePUEvent(gomock.Any(), "b/a", common.EventStop, gomock.Any()).Return(fmt.Errorf("stopping failed")).Times(1)
			handler.EXPECT().HandlePUEvent(gomock.Any(), "b/a", common.EventDestroy, gomock.Any()).Return(fmt.Errorf("stopping failed")).Times(1)
			_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "a", Namespace: "b"}})
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, ErrHandlePUDestroyEventFailed)
		})

		Convey("an existing pod with HostNetwork=true, but host pod activation disabled, should silently return", func() {
			r.enableHostPods = false
			_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "pod2", Namespace: "default"}})
			So(err, ShouldBeNil)
		})

		Convey("a pod which is terminating, should silently return", func() {
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
			// we'll return an error in one case just to get more test coverage
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/failed", common.EventStop, gomock.Any()).Return(fmt.Errorf("stopping failed")).Times(1)
			_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "failed", Namespace: "default"}})
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, ErrHandlePUStopEventFailed)

			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/succeeded", common.EventStop, gomock.Any()).Return(nil).Times(1)
			_, err = r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "succeeded", Namespace: "default"}})
			So(err, ShouldBeNil)

			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/succeeded", common.EventStop, gomock.Any()).Return(policy.ErrPUNotFound("default/succeeded", nil)).Times(1)
			_, err = r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "succeeded", Namespace: "default"}})
			So(err, ShouldBeNil)
		})

		Convey("a pod in pending state should update or create a PU if it does already exist", func() {
			// failing metadata extraction should not matter in all cases
			r.metadataExtractor = metadataExtractorFailure

			// update works
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/pending", common.EventUpdate, gomock.Any()).Return(nil).Times(1)
			_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "pending", Namespace: "default"}})
			So(err, ShouldBeNil)

			// update fails hard
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/pending", common.EventUpdate, gomock.Any()).Return(failure).Times(1)
			_, err = r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "pending", Namespace: "default"}})
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, failure)

			// PU does not exist, but create fails hard
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/pending", common.EventUpdate, gomock.Any()).Return(policy.ErrPUNotFound("default/succeeded", nil)).Times(1)
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/pending", common.EventCreate, gomock.Any()).Return(failure).Times(1)
			_, err = r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "pending", Namespace: "default"}})
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, failure)

			// PU does not exist, but create succeeds
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/pending", common.EventUpdate, gomock.Any()).Return(policy.ErrPUNotFound("default/succeeded", nil)).Times(1)
			handler.EXPECT().HandlePUEvent(gomock.Any(), "default/pending", common.EventCreate, gomock.Any()).Return(nil).Times(1)
			_, err = r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "pending", Namespace: "default"}})
			So(err, ShouldBeNil)
		})

		Convey("a pod which is in running state should silently return if no containers have been started yet", func() {
			_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "runningNotStarted", Namespace: "default"}})
			So(err, ShouldBeNil)
		})

		Convey("a pod which is in running state", func() {
			Convey("should retry if metadata extraction fails", func() {
				r.metadataExtractor = func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
					return nil, failure
				}
				_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "running", Namespace: "default"}})
				So(err, ShouldNotBeNil)
				So(err, ShouldEqual, failure)
			})
			Convey("should retry if metadata extraction succeeded, but no PID nor netns path were found and this is not a hostnetwork pod", func() {
				r.metadataExtractor = func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
					return policy.NewPURuntimeWithDefaults(), nil
				}
				_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "running", Namespace: "default"}})
				So(err, ShouldNotBeNil)
				So(err, ShouldEqual, ErrNetnsExtractionMissing)
			})
			Convey("should fail if metadata and PID/netnspath extraction succeeded, but the Start PU even fails", func() {
				r.metadataExtractor = func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
					return policy.NewPURuntime("default/running", 42, "", nil, nil, common.ContainerPU, nil), nil
				}
				handler.EXPECT().HandlePUEvent(gomock.Any(), "default/running", common.EventStart, gomock.Any()).Return(failure).Times(1)
				_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "running", Namespace: "default"}})
				So(err, ShouldNotBeNil)
				So(err, ShouldEqual, ErrHandlePUStartEventFailed)
			})
			Convey("should return silently if metadata and PID/netnspath extraction succeeded, but the PU has already been activated", func() {
				r.metadataExtractor = func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
					return policy.NewPURuntime("default/running", 42, "", nil, nil, common.ContainerPU, nil), nil
				}
				handler.EXPECT().HandlePUEvent(gomock.Any(), "default/running", common.EventStart, gomock.Any()).Return(policy.ErrPUAlreadyActivated("default/running", nil)).Times(1)
				_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "running", Namespace: "default"}})
				So(err, ShouldBeNil)
			})
			Convey("should return silently if metadata and PID/netnspath extraction succeeded, and the PU could be successfully activated", func() {
				r.metadataExtractor = func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
					return policy.NewPURuntime("default/running", 42, "", nil, nil, common.ContainerPU, nil), nil
				}
				handler.EXPECT().HandlePUEvent(gomock.Any(), "default/running", common.EventStart, gomock.Any()).Return(nil).Times(1)
				_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "running", Namespace: "default"}})
				So(err, ShouldBeNil)
			})
		})

		Convey("a HostNetwork=true pod should try to start the PU and try to program the netcls cgroup", func() {
			r.metadataExtractor = func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
				return policy.NewPURuntime("default/running", 0, "", nil, nil, common.LinuxProcessPU, nil), nil
			}
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
				_, err := r.Reconcile(reconcile.Request{NamespacedName: types.NamespacedName{Name: "runningHostNetwork", Namespace: "default"}})
				So(err, ShouldNotBeNil)
				So(err, ShouldEqual, failure)
			})
		})
	})
}
