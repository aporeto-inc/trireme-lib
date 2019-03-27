package podmonitor

import (
	"context"
	"fmt"
	"testing"
	"time"

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
		c := fakeclient.NewFakeClient(pod1, pod2, pod3)

		handler := mockpolicy.NewMockResolver(ctrl)

		metadataExtractor := func(ctx context.Context, c client.Client, s *runtime.Scheme, p *corev1.Pod, extractNetns bool) (*policy.PURuntime, error) {
			return nil, nil
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

		Convey("a not existing pod should trigger a stop and destroy event, and fails if it cannot handle the destroy", func() {
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
	})
}
