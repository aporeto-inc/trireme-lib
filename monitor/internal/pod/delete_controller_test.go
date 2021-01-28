package podmonitor

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/config"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/policy/mockpolicy"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestDeleteControllerFunctionality(t *testing.T) {
	Convey("Given fake clients and a mock policy resolver", t, func() {
		ctrl := gomock.NewController(t)
		// moved explicitly to below because new tests need more control
		//defer ctrl.Finish()

		nodeName := "test1"
		pod1 := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod1",
				Namespace: "default",
				UID:       types.UID("aaaa"),
			},
			Spec: corev1.PodSpec{
				NodeName: nodeName,
			},
		}
		crc := NewMockClient(ctrl)
		c := NewMockInterface(ctrl)
		cc := NewMockCoreV1Interface(ctrl)
		ccpod := NewMockPodInterface(ctrl)
		c.EXPECT().CoreV1().AnyTimes().Return(cc)
		cc.EXPECT().Pods(gomock.Any()).AnyTimes().Return(ccpod)
		ccpod.EXPECT().Get(gomock.Any(), gomock.Any()).AnyTimes().Return(pod1, nil)
		crc.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(func(_ context.Context, _ types.NamespacedName, obj runtime.Object) error {
			*obj.(*corev1.Pod) = *pod1
			return nil
		})
		eventsCh := make(chan event.GenericEvent)
		go func() {
			for {
				<-eventsCh
			}
		}()
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
			deleteControllerReconcile(ctx, crc, c, nodeName, pc, itemProcessTimeout, m, nil, eventsCh, 0)
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
			deleteControllerReconcile(ctx, crc, c, nodeName, pc, itemProcessTimeout, m, nil, eventsCh, 0)
			So(m, ShouldHaveLength, 1)
		})

		Convey("then a destroy event should be sent if the pod with the same namespaced name and UID still exists in the Kubernetes API, but is now on a different node", func() {
			handler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), common.EventDestroy, gomock.Any()).Return(nil).Times(1)
			m := make(map[string]DeleteObject)
			nn := client.ObjectKey{
				Name:      "pod1",
				Namespace: "default",
			}
			m["aaaa"] = DeleteObject{podUID: "aaaa", sandboxID: "", podName: nn}
			deleteControllerReconcile(ctx, crc, c, "test2", pc, itemProcessTimeout, m, nil, eventsCh, 0)
			So(m, ShouldBeEmpty)
		})

		Convey("then a destroy event should be sent if the pod with the same namespaced name but *different* UID exists in the Kubernetes API", func() {
			handler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), common.EventDestroy, gomock.Any()).Return(nil).Times(1)
			m := make(map[string]DeleteObject)
			nn := client.ObjectKey{
				Name:      "pod1",
				Namespace: "default",
			}
			m["bbbb"] = DeleteObject{podUID: "", sandboxID: "", podName: nn}
			deleteControllerReconcile(ctx, crc, c, nodeName, pc, itemProcessTimeout, m, nil, eventsCh, 0)
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
			deleteControllerReconcile(ctx, crc, c, nodeName, pc, itemProcessTimeout, m, nil, eventsCh, 0)
			So(m, ShouldBeEmpty)
		})

		sandboxExtractor := func(context.Context, *corev1.Pod) (string, error) {
			return "different", nil
		}

		Convey("then a destroy event should be sent if the pod exists in the Kubernetes API, but the sandbox has changed", func() {
			handler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), common.EventDestroy, gomock.Any()).Return(nil).Times(1)
			m := make(map[string]DeleteObject)

			nn := client.ObjectKey{
				Name:      "pod1",
				Namespace: "default",
			}
			m["aaaa"] = DeleteObject{podUID: "aaaa", sandboxID: "sandbox", podName: nn}
			deleteControllerReconcile(ctx, crc, c, nodeName, pc, itemProcessTimeout, m, sandboxExtractor, eventsCh, 0)
			So(m, ShouldBeEmpty)
		})

		ctrl.Finish()

		Convey("then a destroy event should be sent if the pod does not exist in the Kubernetes API", func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			crc := NewMockClient(ctrl)
			c := NewMockInterface(ctrl)
			cc := NewMockCoreV1Interface(ctrl)
			ccpod := NewMockPodInterface(ctrl)
			crc.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(errors.NewNotFound(schema.GroupResource{Resource: "Pod"}, "pod2"))
			c.EXPECT().CoreV1().AnyTimes().Return(cc)
			cc.EXPECT().Pods(gomock.Eq("default")).Times(1).Return(ccpod)
			ccpod.EXPECT().Get(gomock.Eq("pod2"), gomock.Any()).Times(1).Return(nil, errors.NewNotFound(schema.GroupResource{Resource: "Pod"}, "pod2"))
			handler := mockpolicy.NewMockResolver(ctrl)
			pc := &config.ProcessorConfig{
				Policy: handler,
			}

			handler.EXPECT().HandlePUEvent(gomock.Any(), gomock.Any(), common.EventDestroy, gomock.Any()).Return(nil).Times(1)
			m := make(map[string]DeleteObject)

			nn := client.ObjectKey{
				Name:      "pod2",
				Namespace: "default",
			}
			m["aaaa"] = DeleteObject{podUID: "aaaa", sandboxID: "sandbox", podName: nn}
			deleteControllerReconcile(ctx, crc, c, nodeName, pc, itemProcessTimeout, m, nil, eventsCh, 0)
			So(m, ShouldBeEmpty)
		})

		Convey("then a counter should be decreased if the pod does not exist in the Kubernetes API", func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			crc := NewMockClient(ctrl)
			c := NewMockInterface(ctrl)
			cc := NewMockCoreV1Interface(ctrl)
			ccpod := NewMockPodInterface(ctrl)
			crc.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(errors.NewNotFound(schema.GroupResource{Resource: "Pod"}, "pod2"))
			c.EXPECT().CoreV1().AnyTimes().Return(cc)
			cc.EXPECT().Pods(gomock.Eq("default")).Times(1).Return(ccpod)
			ccpod.EXPECT().Get(gomock.Eq("pod2"), gomock.Any()).Times(1).Return(nil, errors.NewNotFound(schema.GroupResource{Resource: "Pod"}, "pod2"))
			handler := mockpolicy.NewMockResolver(ctrl)
			pc := &config.ProcessorConfig{
				Policy: handler,
			}

			m := make(map[string]DeleteObject)

			nn := client.ObjectKey{
				Name:      "pod2",
				Namespace: "default",
			}
			m["aaaa"] = DeleteObject{podUID: "aaaa", sandboxID: "sandbox", podName: nn, getRetryCounter: 3}
			deleteControllerReconcile(ctx, crc, c, nodeName, pc, itemProcessTimeout, m, nil, eventsCh, 3)
			So(m, ShouldNotBeEmpty)
			So(m, ShouldContainKey, "aaaa")
			So(m["aaaa"].getRetryCounter, ShouldEqual, 2)
		})

		Convey("then a counter should be reset if a pod reappears in the Kubernetes API", func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			crc := NewMockClient(ctrl)
			c := NewMockInterface(ctrl)
			cc := NewMockCoreV1Interface(ctrl)
			ccpod := NewMockPodInterface(ctrl)
			crc.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(errors.NewNotFound(schema.GroupResource{Resource: "Pod"}, "pod2"))
			c.EXPECT().CoreV1().AnyTimes().Return(cc)
			cc.EXPECT().Pods(gomock.Eq("default")).Times(1).Return(ccpod)
			ccpod.EXPECT().Get(gomock.Eq("pod1"), gomock.Any()).Times(1).Return(pod1, nil)
			handler := mockpolicy.NewMockResolver(ctrl)
			pc := &config.ProcessorConfig{
				Policy: handler,
			}

			m := make(map[string]DeleteObject)

			nn := client.ObjectKey{
				Name:      "pod1",
				Namespace: "default",
			}
			m["aaaa"] = DeleteObject{podUID: "aaaa", sandboxID: "sandbox", podName: nn, getRetryCounter: 2}
			deleteControllerReconcile(ctx, crc, c, nodeName, pc, itemProcessTimeout, m, nil, eventsCh, 3)
			So(m, ShouldNotBeEmpty)
			So(m, ShouldContainKey, "aaaa")
			So(m["aaaa"].getRetryCounter, ShouldEqual, 3)
		})
	})
}

func TestDeleteController(t *testing.T) {
	Convey("Given a delete controller", t, func() {
		z := make(chan struct{})

		nodeName := "test1"
		testMap := make(map[string]DeleteObject)
		eventsCh := make(chan event.GenericEvent)
		go func() {
			<-eventsCh
		}()
		//nolint:unparam
		reconcileFunc := func(ctx context.Context, c client.Client, vc kubernetes.Interface, nodeName string, pc *config.ProcessorConfig, t time.Duration, m map[string]DeleteObject, s extractors.PodSandboxExtractor, eventsCh chan event.GenericEvent, maxGetRetryCount uint8) {
			for k, v := range m {
				testMap[k] = v
			}
		}

		dc := NewDeleteController(nil, nil, nodeName, nil, nil, eventsCh, 0)
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
