package k8smonitor

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	//kubernetesTesting "k8s.io/client-go/testing"
)

func Test_podCache_Delete(t *testing.T) {
	updateEvent := func(context.Context, string) error {
		return nil
	}

	tests := []struct {
		name      string
		c         *podCache
		sandboxID string
	}{
		{
			name:      "cache uninitialized",
			c:         nil,
			sandboxID: "does-not-matter",
		},
		{
			name:      "cache initialized",
			c:         newPodCache(updateEvent),
			sandboxID: "does-not-mater",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.c.Delete(tt.sandboxID)
		})
	}
}

func Test_podCache_Set(t *testing.T) {
	updateEvent := func(context.Context, string) error {
		return nil
	}
	type args struct {
		sandboxID string
		pod       *corev1.Pod
	}
	tests := []struct {
		name         string
		c            *podCache
		args         args
		wantErr      bool
		wantErrError error
	}{
		{
			name:         "cache uninitialized",
			c:            nil,
			wantErr:      true,
			wantErrError: errCacheUninitialized,
		},
		{
			name:         "cache has unintialized map",
			c:            &podCache{},
			wantErr:      true,
			wantErrError: errCacheUninitialized,
			args: args{
				sandboxID: "does-not-matter",
				pod:       &corev1.Pod{},
			},
		},
		{
			name:         "no sandboxID",
			c:            newPodCache(updateEvent),
			wantErr:      true,
			wantErrError: errSandboxEmpty,
			args: args{
				sandboxID: "",
				pod:       &corev1.Pod{},
			},
		},
		{
			name:         "pod is nil",
			c:            newPodCache(updateEvent),
			wantErr:      true,
			wantErrError: errPodNil,
			args: args{
				sandboxID: "does-not-matter",
				pod:       nil,
			},
		},
		{
			name:    "successful update entry",
			c:       newPodCache(updateEvent),
			wantErr: false,
			args: args{
				sandboxID: "does-not-matter",
				pod:       &corev1.Pod{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.c.Set(tt.args.sandboxID, tt.args.pod)
			if (err != nil) != tt.wantErr {
				t.Errorf("podCache.Set() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if err != tt.wantErrError {
					t.Errorf("podCache.Set() error = %v, wantErrError %v", err, tt.wantErrError)
				}
			}
		})
	}
}

func Test_podCache_Get(t *testing.T) {
	updateEvent := func(context.Context, string) error {
		return nil
	}
	cacheWithEntry := newPodCache(updateEvent)
	if err := cacheWithEntry.Set("entry", &corev1.Pod{}); err != nil {
		panic(err)
	}
	tests := []struct {
		name      string
		sandboxID string
		c         *podCache
		want      *corev1.Pod
	}{
		{
			name: "uninitialized podCache",
			c:    nil,
			want: nil,
		},
		{
			name: "uninitialized map in podCache",
			c:    &podCache{},
			want: nil,
		},
		{
			name:      "entry does not exist",
			c:         newPodCache(updateEvent),
			sandboxID: "does-not-exist",
			want:      nil,
		},
		{
			name:      "entry exists",
			c:         cacheWithEntry,
			sandboxID: "entry",
			want:      &corev1.Pod{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.Get(tt.sandboxID); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("podCache.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_podCache_FindSandboxID(t *testing.T) {
	updateEvent := func(context.Context, string) error {
		return nil
	}
	cacheWithEntry := newPodCache(updateEvent)
	if err := cacheWithEntry.Set("entry", &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-pod",
			Namespace: "default",
		},
	}); err != nil {
		panic(err)
	}
	type args struct {
		name      string
		namespace string
	}
	tests := []struct {
		name         string
		c            *podCache
		args         args
		want         string
		wantErr      bool
		wantErrError error
	}{
		{
			name:         "cache uninitialized",
			c:            nil,
			wantErr:      true,
			wantErrError: errCacheUninitialized,
		},
		{
			name:         "pods uninitialized",
			c:            &podCache{},
			wantErr:      true,
			wantErrError: errCacheUninitialized,
		},
		{
			name: "pod name empty",
			c:    newPodCache(updateEvent),
			args: args{
				name:      "",
				namespace: "default",
			},
			wantErr:      true,
			wantErrError: errPodNameEmpty,
		},
		{
			name: "pod namespace empty",
			c:    newPodCache(updateEvent),
			args: args{
				name:      "my-pod",
				namespace: "",
			},
			wantErr:      true,
			wantErrError: errPodNamespaceEmpty,
		},
		{
			name: "sandbox not found",
			c:    newPodCache(updateEvent),
			args: args{
				name:      "my-pod",
				namespace: "default",
			},
			wantErr:      true,
			wantErrError: errSandboxNotFound,
		},
		{
			name: "sandbox found",
			c:    cacheWithEntry,
			args: args{
				name:      "my-pod",
				namespace: "default",
			},
			wantErr: false,
			want:    "entry",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.c.FindSandboxID(tt.args.name, tt.args.namespace)
			if (err != nil) != tt.wantErr {
				t.Errorf("podCache.FindSandboxID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("podCache.FindSandboxID() = %v, want %v", got, tt.want)
			}
			if tt.wantErr {
				if err != tt.wantErrError {
					t.Errorf("podCache.FindSandboxID() error = %v, wantErrError %v", err, tt.wantErrError)
				}
			}
		})
	}
}

type unitTestUpdateEvent interface {
	f() updateEventFunc
	wait()
	called() bool
}
type unitTestUpdateEventHandler struct {
	sync.RWMutex
	wg        sync.WaitGroup
	wgCounter int
	wasCalled bool
	err       error
}

func (h *unitTestUpdateEventHandler) updateEvent(context.Context, string) error {
	h.Lock()
	defer h.Unlock()
	h.wasCalled = true
	if h.wgCounter > 0 {
		h.wgCounter--
	}
	if h.wgCounter >= 0 {
		h.wg.Done()
	}
	return h.err
}

func (h *unitTestUpdateEventHandler) f() updateEventFunc {
	return h.updateEvent
}

func (h *unitTestUpdateEventHandler) wait() {
	h.wg.Wait()
}

func (h *unitTestUpdateEventHandler) called() bool {
	h.RLock()
	defer h.RUnlock()
	return h.wasCalled
}

func newUnitTestUpdateEventHandler(n int, err error) unitTestUpdateEvent {
	h := &unitTestUpdateEventHandler{
		err:       err,
		wgCounter: n,
	}
	h.wg.Add(n)
	return h
}

func Test_podCache_SetupInformer(t *testing.T) {
	podTemplate := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			NodeName: "test",
		},
	}
	running := corev1.ContainerStateRunning{}
	pending := corev1.ContainerStateWaiting{}

	hostpodTemplate := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-host-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			NodeName:    "test",
			HostNetwork: true,
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			InitContainerStatuses: []corev1.ContainerStatus{
				{
					ContainerID: "testing://containerID",
					Ready:       true,
					State: corev1.ContainerState{
						Waiting: &pending,
					},
				},
			},
			ContainerStatuses: []corev1.ContainerStatus{
				{
					ContainerID: "broken-container-id-needs-to-be-skipped",
					Ready:       true,
					State: corev1.ContainerState{
						Waiting: &pending,
					},
				},
			},
		},
	}
	updateHostPodTemplate := hostpodTemplate.DeepCopy()
	updateHostPodTemplate.Status.InitContainerStatuses[0].State.Running = &running
	updateHostPodTemplate2 := updateHostPodTemplate.DeepCopy()
	updateHostPodTemplate2.Labels = map[string]string{
		"a": "b",
	}

	updatedPodTemplate := podTemplate.DeepCopy()
	updatedPodTemplate.Labels = map[string]string{
		"a": "b",
	}
	updatedPodTemplate2 := updatedPodTemplate.DeepCopy()
	updatedPodTemplate2.Annotations = map[string]string{
		"annotated": "",
	}

	untrackedPodOnSameHostTemplate := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "untracked-same-host",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			NodeName: "test",
		},
	}
	untrackedPodOnDifferentHostTemplate := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "untracked-different-host",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			NodeName: "different",
		},
	}

	c := fake.NewSimpleClientset(
		podTemplate.DeepCopy(),
		untrackedPodOnSameHostTemplate.DeepCopy(),
		untrackedPodOnDifferentHostTemplate.DeepCopy(),
		hostpodTemplate.DeepCopy(),
	)

	type fields struct {
		pods map[string]*corev1.Pod
	}
	type args struct {
		ctx         context.Context
		kubeClient  kubernetes.Interface
		nodeName    string
		needsUpdate needsUpdateFunc
	}
	tests := []struct {
		name                string
		updateEventHandler  unitTestUpdateEvent
		fields              fields
		args                args
		action              func(*testing.T, *podCache)
		expectedUpdateEvent bool
		expectedPods        map[string]*corev1.Pod
	}{
		{
			name:               "update to a pod which we have in cache which requires update event",
			updateEventHandler: newUnitTestUpdateEventHandler(1, fmt.Errorf("increase coverage")),
			fields: fields{
				pods: map[string]*corev1.Pod{
					"entry": podTemplate.DeepCopy(),
				},
			},
			args: args{
				ctx:         context.Background(),
				kubeClient:  c,
				nodeName:    "test",
				needsUpdate: defaultNeedsUpdate,
			},
			action: func(_ *testing.T, _ *podCache) {
				_, err := c.CoreV1().Pods("default").Update(context.Background(), updatedPodTemplate.DeepCopy(), metav1.UpdateOptions{})
				if err != nil {
					panic(err)
				}
			},
			expectedUpdateEvent: true,
			expectedPods: map[string]*corev1.Pod{
				"entry": updatedPodTemplate.DeepCopy(),
			},
		},
		{
			name:               "update to a pod which we have in cache which does not require an update event",
			updateEventHandler: newUnitTestUpdateEventHandler(0, nil),
			fields: fields{
				pods: map[string]*corev1.Pod{
					"entry": podTemplate.DeepCopy(),
				},
			},
			args: args{
				ctx:         context.Background(),
				kubeClient:  c,
				nodeName:    "test",
				needsUpdate: defaultNeedsUpdate,
			},
			action: func(_ *testing.T, _ *podCache) {
				_, err := c.CoreV1().Pods("default").Update(context.Background(), updatedPodTemplate2.DeepCopy(), metav1.UpdateOptions{})
				if err != nil {
					panic(err)
				}
				time.Sleep(time.Millisecond * 100)
			},
			expectedUpdateEvent: false,
			expectedPods: map[string]*corev1.Pod{
				"entry": updatedPodTemplate2.DeepCopy(),
			},
		},
		{
			name:               "update to a pod from different host which we do not track",
			updateEventHandler: newUnitTestUpdateEventHandler(0, nil),
			fields: fields{
				pods: map[string]*corev1.Pod{
					"entry": podTemplate.DeepCopy(),
				},
			},
			args: args{
				ctx:         context.Background(),
				kubeClient:  c,
				nodeName:    "test",
				needsUpdate: defaultNeedsUpdate,
			},
			action: func(_ *testing.T, _ *podCache) {
				updated := untrackedPodOnDifferentHostTemplate.DeepCopy()
				updated.Labels = map[string]string{
					"update": "",
				}
				_, err := c.CoreV1().Pods("default").Update(context.Background(), updated.DeepCopy(), metav1.UpdateOptions{})
				if err != nil {
					panic(err)
				}
			},
			expectedUpdateEvent: false,
			expectedPods: map[string]*corev1.Pod{
				"entry": podTemplate.DeepCopy(),
			},
		},
		{
			name:               "update to a pod from the same host which we do not track",
			updateEventHandler: newUnitTestUpdateEventHandler(0, nil),
			fields: fields{
				pods: map[string]*corev1.Pod{
					"entry": podTemplate.DeepCopy(),
				},
			},
			args: args{
				ctx:         context.Background(),
				kubeClient:  c,
				nodeName:    "test",
				needsUpdate: defaultNeedsUpdate,
			},
			action: func(_ *testing.T, _ *podCache) {
				updated := untrackedPodOnSameHostTemplate.DeepCopy()
				updated.Labels = map[string]string{
					"update": "",
				}
				_, err := c.CoreV1().Pods("default").Update(context.Background(), updated.DeepCopy(), metav1.UpdateOptions{})
				if err != nil {
					panic(err)
				}
			},
			expectedUpdateEvent: false,
			expectedPods: map[string]*corev1.Pod{
				"entry": podTemplate.DeepCopy(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &podCache{
				pods:        tt.fields.pods,
				updateEvent: tt.updateEventHandler.f(),
			}
			ctx, cancel := context.WithCancel(tt.args.ctx)
			c.SetupInformer(ctx, tt.args.kubeClient, tt.args.nodeName, tt.args.needsUpdate)
			tt.action(t, c)
			tt.updateEventHandler.wait()
			c.RLock()
			if !reflect.DeepEqual(c.pods, tt.expectedPods) {
				t.Errorf("c.pods = %v, want %v", c.pods, tt.expectedPods)
			}
			c.RUnlock()
			if tt.expectedUpdateEvent != tt.updateEventHandler.called() {
				t.Errorf("updateEventHandler.called() = %v, want %v", tt.updateEventHandler.called(), tt.expectedUpdateEvent)
			}
			cancel()
		})
	}
}

func Test_defaultNeedsUpdate(t *testing.T) {
	type args struct {
		prev *corev1.Pod
		obj  *corev1.Pod
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "labels are both nil",
			args: args{
				prev: &corev1.Pod{},
				obj:  &corev1.Pod{},
			},
			want: false,
		},
		{
			name: "labels are empty",
			args: args{
				prev: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{},
					},
				},
				obj: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{},
					},
				},
			},
			want: false,
		},
		{
			name: "labels are the same",
			args: args{
				prev: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"a": "b",
						},
					},
				},
				obj: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"a": "b",
						},
					},
				},
			},
			want: false,
		},
		{
			name: "labels are the same, but one has annotations",
			args: args{
				prev: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"a": "b",
						},
					},
				},
				obj: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"a": "b",
						},
						Annotations: map[string]string{
							"a": "b",
						},
					},
				},
			},
			want: false,
		},
		{
			name: "labels are nil in prev, but set on new",
			args: args{
				prev: &corev1.Pod{},
				obj: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"a": "b",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "labels are empty in prev, but set on new",
			args: args{
				prev: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{},
					},
				},
				obj: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"a": "b",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "labels have same key but different value",
			args: args{
				prev: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"a": "a",
						},
					},
				},
				obj: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"a": "b",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "prev has one label more",
			args: args{
				prev: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"a": "b",
							"b": "b",
						},
					},
				},
				obj: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"a": "b",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "prev has different labels",
			args: args{
				prev: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"b": "b",
						},
					},
				},
				obj: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"a": "b",
						},
					},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := defaultNeedsUpdate(tt.args.prev, tt.args.obj); got != tt.want {
				t.Errorf("defaultNeedsUpdate() = %v, want %v", got, tt.want)
			}
		})
	}
}
