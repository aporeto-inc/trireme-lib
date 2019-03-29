package podmonitor

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/handler"
)

func TestWatchPodMapper(t *testing.T) {
	Convey("Given a watch pod mapper and a pod", t, func() {
		m := WatchPodMapper{
			// client is currently not in use for this mapper
			client:         nil,
			nodeName:       "testing-node",
			enableHostPods: true,
		}
		p := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "p1",
			},
			Spec: corev1.PodSpec{
				NodeName: "testing-node",
			},
		}
		Convey("do not reconcile if the object is not a pod", func() {
			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "service",
				},
			}
			reqs := m.Map(handler.MapObject{Meta: svc.GetObjectMeta(), Object: svc})
			So(reqs, ShouldHaveLength, 0)
		})
		Convey("do not reconcile if the node name does not match", func() {
			p.Spec.NodeName = "wrong"
			reqs := m.Map(handler.MapObject{Meta: p.GetObjectMeta(), Object: p})
			So(reqs, ShouldHaveLength, 0)
		})
		Convey("do not reconcile if enabling host pods is not enabled, but the pod has HostNetwork set to true", func() {
			m.enableHostPods = false
			p.Spec.HostNetwork = true
			reqs := m.Map(handler.MapObject{Meta: p.GetObjectMeta(), Object: p})
			So(reqs, ShouldHaveLength, 0)
		})
		Convey("reconcile if the node name matches", func() {
			reqs := m.Map(handler.MapObject{Meta: p.GetObjectMeta(), Object: p})
			So(reqs, ShouldHaveLength, 1)
		})
	})
}
