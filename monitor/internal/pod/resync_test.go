package podmonitor

import (
	"context"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestResyncWithAllPods(t *testing.T) {
	Convey("Given a client, two pods and an event channel", t, func() {
		ctx := context.TODO()
		evCh := make(chan event.GenericEvent, 100)
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
		}
		c := fakeclient.NewFakeClient(pod1, pod2)

		Convey("resync should fail if there is no client", func() {
			err := ResyncWithAllPods(ctx, nil, evCh)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "pod: no client available")
		})

		Convey("resync should fail if there is no event channel", func() {
			err := ResyncWithAllPods(ctx, c, nil)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "pod: no event source available")
		})

		Convey("resync should successfully send messages with all pods", func() {
			err := ResyncWithAllPods(ctx, c, evCh)
			So(err, ShouldBeNil)
			allPods := []string{"pod1", "pod2"}
			collectedPods := []string{}

			obj1 := <-evCh
			So(obj1.Meta.GetName(), ShouldBeIn, allPods)
			collectedPods = append(collectedPods, obj1.Meta.GetName())
			obj2 := <-evCh
			So(obj2.Meta.GetName(), ShouldBeIn, allPods)
			collectedPods = append(collectedPods, obj2.Meta.GetName())
			So("pod1", ShouldBeIn, collectedPods)
			So("pod2", ShouldBeIn, collectedPods)
			So(obj1.Meta.GetName(), ShouldNotEqual, obj2.Meta.GetName())
		})
	})
}
