package podmonitor

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/v11/common"
	"go.aporeto.io/trireme-lib/v11/monitor/config"
	"go.aporeto.io/trireme-lib/v11/monitor/extractors"
	"go.aporeto.io/trireme-lib/v11/policy/mockpolicy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestDeleteControllerFunctionality(t *testing.T) {
	Convey("Given a fake controller-runtime client and a mock policy resolver", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		pod1 := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod1",
				Namespace: "default",
				UID:       types.UID("aaaa"),
			},
		}
		c := fakeclient.NewFakeClient(pod1)
		eventsCh := make(chan event.GenericEvent)
		handler := mockpolicy.NewMockResolver(ctrl)

		pc := &config.ProcessorConfig{
			Policy: handler,
		}

		ctx := context.Background()
		itemProcessTimeout := 5 * time.Second

		failure := fmt.Errorf("failure")

		Convey("then no destroy events should be sent if there is nothing in the state right now", func() {
			handler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), common.EventDestroy, gomock.Any()).Return(nil).Times(0)
			m := make(map[string]DeleteObject)
			deleteControllerReconcile(ctx, c, pc, itemProcessTimeout, m, nil, eventsCh)
			So(m, ShouldBeEmpty)
		})

		Convey("then *no* destroy events should be sent if the pod with the same namespaced name and UID still exists in the Kubernetes API", func() {
			handler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), common.EventDestroy, gomock.Any()).Return(nil).Times(0)
			m := make(map[string]DeleteObject)
			nn := client.ObjectKey{
				Name:      "pod1",
				Namespace: "default",
			}
			m["aaaa"] = DeleteObject{podUID: "aaaa", sandboxID: "", podName: nn}
			deleteControllerReconcile(ctx, c, pc, itemProcessTimeout, m, nil, eventsCh)
			So(m, ShouldHaveLength, 1)
		})

		Convey("then a destroy event should be sent if the pod with the same namespaced name but *different* UID exists in the Kubernetes API", func() {
			handler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), common.EventDestroy, gomock.Any()).Return(nil).Times(1)
			m := make(map[string]DeleteObject)
			nn := client.ObjectKey{
				Name:      "pod1",
				Namespace: "default",
			}
			m["bbbb"] = DeleteObject{podUID: "", sandboxID: "", podName: nn}
			deleteControllerReconcile(ctx, c, pc, itemProcessTimeout, m, nil, eventsCh)
			So(m, ShouldBeEmpty)
		})

		Convey("then a destroy event should be sent if the pod does not exist in the Kubernetes API", func() {
			handler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), common.EventDestroy, gomock.Any()).Return(nil).Times(1)
			m := make(map[string]DeleteObject)

			nn := client.ObjectKey{
				Name:      "pod2",
				Namespace: "default",
			}
			m["aaaa"] = DeleteObject{podUID: "", sandboxID: "", podName: nn}
			deleteControllerReconcile(ctx, c, pc, itemProcessTimeout, m, nil, eventsCh)
			So(m, ShouldBeEmpty)
		})

		Convey("then a destroy event should be sent if the pod with the same namespaced name but *different* UID exists in the Kubernetes API, and it should still be removed from the map if it fails", func() {
			handler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), common.EventDestroy, gomock.Any()).Return(failure).Times(1)
			m := make(map[string]DeleteObject)

			nn := client.ObjectKey{
				Name:      "pod1",
				Namespace: "default",
			}
			m["bbbb"] = DeleteObject{podUID: "", sandboxID: "", podName: nn}
			deleteControllerReconcile(ctx, c, pc, itemProcessTimeout, m, nil, eventsCh)
			So(m, ShouldBeEmpty)
		})

		Convey("then a destroy event should be sent if the pod does not exist in the Kubernetes API, and it should still be removed from the map if it fails", func() {
			handler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), common.EventDestroy, gomock.Any()).Return(failure).Times(1)
			m := make(map[string]DeleteObject)

			nn := client.ObjectKey{
				Name:      "pod2",
				Namespace: "default",
			}
			m["aaaa"] = DeleteObject{podUID: "", sandboxID: "", podName: nn}
			deleteControllerReconcile(ctx, c, pc, itemProcessTimeout, m, nil, eventsCh)
			So(m, ShouldBeEmpty)
		})
	})
}

func TestDeleteController(t *testing.T) {
	Convey("Given a delete controller", t, func() {
		z := make(chan struct{})

		testMap := make(map[string]DeleteObject)
		eventsCh := make(chan event.GenericEvent)
		//nolint:unparam
		reconcileFunc := func(ctx context.Context, c client.Client, pc *config.ProcessorConfig, t time.Duration, m map[string]DeleteObject, s extractors.PodSandboxExtractor, eventsCh chan event.GenericEvent) {
			for k, v := range m {
				testMap[k] = v
			}
		}

		dc := NewDeleteController(nil, nil, nil, eventsCh)
		dc.deleteCh = make(chan DeleteEvent)
		dc.reconcileCh = make(chan struct{})
		dc.tickerPeriod = 1 * time.Second
		dc.itemProcessTimeout = 1 * time.Second
		dc.reconcileFunc = reconcileFunc

		Convey("it should be able to receive delete events, and access them during a reconcile", func() {
			ev := DeleteEvent{
				PodUID: "aaaa",
				NamespaceName: client.ObjectKey{
					Name:      "pod1",
					Namespace: "default",
				},
			}
			exp := DeleteObject{
				podUID:    "aaaa",
				sandboxID: "",
				podName: client.ObjectKey{
					Name:      "pod1",
					Namespace: "default",
				},
			}
			go func() {
				dc.GetDeleteCh() <- ev
				dc.GetReconcileCh() <- struct{}{}
				close(z)
			}()

			err := dc.Start(z)
			So(err, ShouldBeNil)
			So(testMap, ShouldContainKey, ev.PodUID)
			So(testMap[ev.PodUID], ShouldResemble, exp)
		})

		Convey("it should be able to receive delete events, and access them during a reconcile that was triggered through the ticker", func() {
			ev := DeleteEvent{
				PodUID: "aaaa",
				NamespaceName: client.ObjectKey{
					Name:      "pod1",
					Namespace: "default",
				},
			}
			exp := DeleteObject{
				podUID:    "aaaa",
				sandboxID: "",
				podName: client.ObjectKey{
					Name:      "pod1",
					Namespace: "default",
				},
			}
			go func() {
				dc.GetDeleteCh() <- ev
				// sleeping for twice the ticker period should always trigger the reconcile
				time.Sleep(dc.tickerPeriod * 2)
				close(z)
			}()

			err := dc.Start(z)
			So(err, ShouldBeNil)
			So(testMap, ShouldContainKey, ev.PodUID)
			So(testMap[ev.PodUID], ShouldResemble, exp)
		})

		Reset(func() {
			testMap = make(map[string]DeleteObject)
			dc = &DeleteController{
				client:             nil,
				handler:            nil,
				deleteCh:           make(chan DeleteEvent),
				reconcileCh:        make(chan struct{}),
				tickerPeriod:       1 * time.Second,
				itemProcessTimeout: 1 * time.Second,
				reconcileFunc:      reconcileFunc,
			}
		})
	})
}
