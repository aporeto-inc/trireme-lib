// +build !windows

package kubernetesmonitor

import (
	"reflect"
	"sync"
	"testing"

	"go.aporeto.io/trireme-lib/v11/policy"
)

func Test_cache_updatePUIDCache(t *testing.T) {

	// Pregenerating a couple fake runtimes
	runtime1 := policy.NewPURuntimeWithDefaults()
	runtime1.SetPid(1)
	runtime2 := policy.NewPURuntimeWithDefaults()
	runtime2.SetPid(2)
	runtime3 := policy.NewPURuntimeWithDefaults()
	runtime3.SetPid(3)

	type fields struct {
		puidCache map[string]*puidCacheEntry
		podCache  map[string]*podCacheEntry
		RWMutex   sync.RWMutex
	}
	type args struct {
		podNamespace      string
		podName           string
		puID              string
		dockerRuntime     policy.RuntimeReader
		kubernetesRuntime policy.RuntimeReader
	}
	tests := []struct {
		name         string
		fields       *fields
		fieldsResult *fields
		args         *args
	}{
		{
			name: "test empty all",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{},
				podCache:  map[string]*podCacheEntry{},
			},
			fieldsResult: &fields{
				puidCache: map[string]*puidCacheEntry{},
				podCache:  map[string]*podCacheEntry{},
			},
			args: &args{
				podNamespace:      "",
				podName:           "",
				puID:              "",
				dockerRuntime:     policy.NewPURuntimeWithDefaults(),
				kubernetesRuntime: policy.NewPURuntimeWithDefaults(),
			},
		},
		{
			name: "test empty NS",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{},
				podCache:  map[string]*podCacheEntry{},
			},
			fieldsResult: &fields{
				puidCache: map[string]*puidCacheEntry{},
				podCache:  map[string]*podCacheEntry{},
			},
			args: &args{
				podNamespace:      "",
				podName:           "xcvxcv",
				puID:              "xcvxcv",
				dockerRuntime:     policy.NewPURuntimeWithDefaults(),
				kubernetesRuntime: policy.NewPURuntimeWithDefaults(),
			},
		},
		{
			name: "test empty Name",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{},
				podCache:  map[string]*podCacheEntry{},
			},
			fieldsResult: &fields{
				puidCache: map[string]*puidCacheEntry{},
				podCache:  map[string]*podCacheEntry{},
			},
			args: &args{
				podNamespace:      "xcvxcv",
				podName:           "",
				puID:              "xcvxcv",
				dockerRuntime:     policy.NewPURuntimeWithDefaults(),
				kubernetesRuntime: policy.NewPURuntimeWithDefaults(),
			},
		},
		{
			name: "test empty PUID",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{},
				podCache:  map[string]*podCacheEntry{},
			},
			fieldsResult: &fields{
				puidCache: map[string]*puidCacheEntry{},
				podCache:  map[string]*podCacheEntry{},
			},
			args: &args{
				podNamespace:      "xcvxcv",
				podName:           "xcvxcv",
				puID:              "",
				dockerRuntime:     policy.NewPURuntimeWithDefaults(),
				kubernetesRuntime: policy.NewPURuntimeWithDefaults(),
			},
		},
		{
			name: "test normal behavior",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{},
				podCache:  map[string]*podCacheEntry{},
			},
			fieldsResult: &fields{
				puidCache: map[string]*puidCacheEntry{
					"123456": {
						kubeIdentifier:    "namespace/name",
						dockerRuntime:     runtime1,
						kubernetesRuntime: runtime2,
					},
				},
				podCache: map[string]*podCacheEntry{
					"namespace/name": {
						puIDs: map[string]bool{
							"123456": true,
						},
					},
				},
			},
			args: &args{
				podNamespace:      "namespace",
				podName:           "name",
				puID:              "123456",
				dockerRuntime:     runtime1,
				kubernetesRuntime: runtime2,
			},
		},
		{
			name: "test additive behavior",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{
					"123456": {
						kubeIdentifier:    "namespace/name",
						dockerRuntime:     runtime1,
						kubernetesRuntime: runtime2,
					},
				},
				podCache: map[string]*podCacheEntry{
					"namespace/name": {
						puIDs: map[string]bool{
							"123456": true,
						},
					},
				},
			},
			fieldsResult: &fields{
				puidCache: map[string]*puidCacheEntry{
					"123456": {
						kubeIdentifier:    "namespace/name",
						dockerRuntime:     runtime1,
						kubernetesRuntime: runtime2,
					},
					"abcdef": {
						kubeIdentifier:    "namespace2/name2",
						dockerRuntime:     runtime3,
						kubernetesRuntime: runtime2,
					},
				},
				podCache: map[string]*podCacheEntry{
					"namespace/name": {
						puIDs: map[string]bool{
							"123456": true,
						},
					},
					"namespace2/name2": {
						puIDs: map[string]bool{
							"abcdef": true,
						},
					},
				},
			},
			args: &args{
				podNamespace:      "namespace2",
				podName:           "name2",
				puID:              "abcdef",
				dockerRuntime:     runtime3,
				kubernetesRuntime: runtime2,
			},
		},
		{
			name: "test additive same pod",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{
					"123456": {
						kubeIdentifier:    "namespace/name",
						dockerRuntime:     runtime1,
						kubernetesRuntime: runtime2,
					},
				},
				podCache: map[string]*podCacheEntry{
					"namespace/name": {
						puIDs: map[string]bool{
							"123456": true,
						},
					},
				},
			},
			fieldsResult: &fields{
				puidCache: map[string]*puidCacheEntry{
					"123456": {
						kubeIdentifier:    "namespace/name",
						dockerRuntime:     runtime1,
						kubernetesRuntime: runtime2,
					},
					"abcdef": {
						kubeIdentifier:    "namespace/name",
						dockerRuntime:     runtime3,
						kubernetesRuntime: runtime2,
					},
				},
				podCache: map[string]*podCacheEntry{
					"namespace/name": {
						puIDs: map[string]bool{
							"123456": true,
							"abcdef": true,
						},
					},
				},
			},
			args: &args{
				podNamespace:      "namespace",
				podName:           "name",
				puID:              "abcdef",
				dockerRuntime:     runtime3,
				kubernetesRuntime: runtime2,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &cache{
				puidCache: tt.fields.puidCache,
				podCache:  tt.fields.podCache,
			}
			c.updatePUIDCache(tt.args.podNamespace, tt.args.podName, tt.args.puID, tt.args.dockerRuntime, tt.args.kubernetesRuntime)
			if !reflect.DeepEqual(c.puidCache, tt.fieldsResult.puidCache) {
				t.Errorf("updatePUIDCache() field. got %v, want %v", c.puidCache, tt.fieldsResult.puidCache)
			}
			if !reflect.DeepEqual(c.podCache, tt.fieldsResult.podCache) {
				t.Errorf("updatePUIDCache() field. got %v, want %v", c.podCache, tt.fieldsResult.podCache)
			}
		})
	}
}

func Test_cache_getPUIDsbyPod(t *testing.T) {
	puid1 := "12350"
	pod1 := "test/test5"
	puidEntry1 := &puidCacheEntry{
		kubeIdentifier: pod1,
	}
	podEntry1 := &podCacheEntry{
		puIDs: map[string]bool{
			puid1: true,
		},
	}

	type fields struct {
		puidCache map[string]*puidCacheEntry
		podCache  map[string]*podCacheEntry
		RWMutex   sync.RWMutex
	}
	type args struct {
		podNamespace string
		podName      string
	}
	tests := []struct {
		name   string
		fields *fields
		args   *args
		want   []string
	}{
		{
			name: "simple get",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{
					puid1: puidEntry1,
				},
				podCache: map[string]*podCacheEntry{
					pod1: podEntry1,
				},
			},
			args: &args{
				podName:      "test5",
				podNamespace: "test",
			},
			want: []string{puid1},
		},
		{
			name: "non existing",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{
					puid1: puidEntry1,
				},
				podCache: map[string]*podCacheEntry{
					pod1: podEntry1,
				},
			},
			args: &args{
				podName:      "test1",
				podNamespace: "test",
			},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &cache{
				puidCache: tt.fields.puidCache,
				podCache:  tt.fields.podCache,
			}
			if got := c.getPUIDsbyPod(tt.args.podNamespace, tt.args.podName); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("cache.getPUIDsbyPod() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_cache_getDockerRuntimeByPUID(t *testing.T) {

	puid1 := "12346"
	pod1 := "test/test1"
	containerRuntime := policy.NewPURuntimeWithDefaults()
	containerRuntime.SetPid(123)
	puidEntry1 := &puidCacheEntry{
		kubeIdentifier: pod1,
		dockerRuntime:  containerRuntime,
	}
	podEntry1 := &podCacheEntry{
		puIDs: map[string]bool{
			puid1: true,
		},
	}

	type fields struct {
		puidCache map[string]*puidCacheEntry
		podCache  map[string]*podCacheEntry
		RWMutex   sync.RWMutex
	}
	type args struct {
		puid string
	}
	tests := []struct {
		name   string
		fields *fields
		args   *args
		want   policy.RuntimeReader
	}{
		{
			name: "simple get",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{
					puid1: puidEntry1,
				},
				podCache: map[string]*podCacheEntry{
					pod1: podEntry1,
				},
			},
			args: &args{
				puid: puid1,
			},
			want: containerRuntime,
		},
		{
			name: "empty get",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{
					puid1: puidEntry1,
				},
				podCache: map[string]*podCacheEntry{
					pod1: podEntry1,
				},
			},
			args: &args{
				puid: "123123",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &cache{
				puidCache: tt.fields.puidCache,
				podCache:  tt.fields.podCache,
			}
			if got := c.getDockerRuntimeByPUID(tt.args.puid); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("cache.getDockerRuntimeByPUID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_cache_getKubernetesRuntimeByPUID(t *testing.T) {

	puid1 := "12347"
	pod1 := "test/test2"
	containerRuntime := policy.NewPURuntimeWithDefaults()
	containerRuntime.SetPid(123)
	puidEntry1 := &puidCacheEntry{
		kubeIdentifier:    pod1,
		kubernetesRuntime: containerRuntime,
	}
	podEntry1 := &podCacheEntry{
		puIDs: map[string]bool{
			puid1: true,
		},
	}

	type fields struct {
		puidCache map[string]*puidCacheEntry
		podCache  map[string]*podCacheEntry
		RWMutex   sync.RWMutex
	}
	type args struct {
		puid string
	}
	tests := []struct {
		name   string
		fields *fields
		args   *args
		want   policy.RuntimeReader
	}{
		{
			name: "simple get",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{
					puid1: puidEntry1,
				},
				podCache: map[string]*podCacheEntry{
					pod1: podEntry1,
				},
			},
			args: &args{
				puid: puid1,
			},
			want: containerRuntime,
		},
		{
			name: "empty get",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{
					puid1: puidEntry1,
				},
				podCache: map[string]*podCacheEntry{
					pod1: podEntry1,
				},
			},
			args: &args{
				puid: "123123",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &cache{
				puidCache: tt.fields.puidCache,
				podCache:  tt.fields.podCache,
			}
			if got := c.getKubernetesRuntimeByPUID(tt.args.puid); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("cache.getKubernetesRuntimeByPUID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_cache_deletePodEntry(t *testing.T) {

	puid1 := "12348"
	pod1 := "test/test3"
	containerRuntime := policy.NewPURuntimeWithDefaults()
	containerRuntime.SetPid(123)
	puidEntry1 := &puidCacheEntry{
		kubeIdentifier:    pod1,
		kubernetesRuntime: containerRuntime,
	}
	podEntry1 := &podCacheEntry{
		puIDs: map[string]bool{
			puid1: true,
		},
	}

	type fields struct {
		puidCache map[string]*puidCacheEntry
		podCache  map[string]*podCacheEntry
		RWMutex   sync.RWMutex
	}
	type args struct {
		podNamespace string
		podName      string
	}
	tests := []struct {
		name   string
		fields *fields
		args   *args
		want1  map[string]*puidCacheEntry
		want2  map[string]*podCacheEntry
	}{
		{
			name: "simple delete",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{
					puid1: puidEntry1,
				},
				podCache: map[string]*podCacheEntry{
					pod1: podEntry1,
				},
			},
			args: &args{
				podName:      "test3",
				podNamespace: "test",
			},
			want1: map[string]*puidCacheEntry{
				puid1: puidEntry1,
			},
			want2: map[string]*podCacheEntry{},
		},
		{
			name: "non mexisting delete",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{
					puid1: puidEntry1,
				},
				podCache: map[string]*podCacheEntry{
					pod1: podEntry1,
				},
			},
			args: &args{
				podName:      "test2",
				podNamespace: "test",
			},
			want1: map[string]*puidCacheEntry{
				puid1: puidEntry1,
			},
			want2: map[string]*podCacheEntry{
				pod1: podEntry1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &cache{
				puidCache: tt.fields.puidCache,
				podCache:  tt.fields.podCache,
			}
			c.deletePodEntry(tt.args.podNamespace, tt.args.podName)

			if got := tt.fields.puidCache; !reflect.DeepEqual(got, tt.want1) {
				t.Errorf("after cache.deleteByPod = %v, want %v", got, tt.want1)
			}
			if got := tt.fields.podCache; !reflect.DeepEqual(got, tt.want2) {
				t.Errorf("after cache.deleteByPod = %v, want %v", got, tt.want2)
			}
		})
	}
}

func Test_cache_deletePUIDEntry(t *testing.T) {

	puid1 := "12349"
	pod1 := "test/test4"
	containerRuntime := policy.NewPURuntimeWithDefaults()
	containerRuntime.SetPid(123)
	puidEntry1 := &puidCacheEntry{
		kubeIdentifier:    pod1,
		kubernetesRuntime: containerRuntime,
	}
	podEntry1 := &podCacheEntry{
		puIDs: map[string]bool{
			puid1: true,
		},
	}

	type fields struct {
		puidCache map[string]*puidCacheEntry
		podCache  map[string]*podCacheEntry
		RWMutex   sync.RWMutex
	}
	type args struct {
		puid string
	}
	tests := []struct {
		name   string
		fields *fields
		args   *args
		want1  map[string]*puidCacheEntry
		want2  map[string]*podCacheEntry
	}{
		{
			name: "simple delete",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{
					puid1: puidEntry1,
				},
				podCache: map[string]*podCacheEntry{
					pod1: podEntry1,
				},
			},
			args: &args{
				puid: puid1,
			},
			want1: map[string]*puidCacheEntry{},
			want2: map[string]*podCacheEntry{
				pod1: podEntry1,
			},
		},
		{
			name: "non mexisting delete",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{
					puid1: puidEntry1,
				},
				podCache: map[string]*podCacheEntry{
					pod1: podEntry1,
				},
			},
			args: &args{
				puid: "123123",
			},
			want1: map[string]*puidCacheEntry{
				puid1: puidEntry1,
			},
			want2: map[string]*podCacheEntry{
				pod1: podEntry1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &cache{
				puidCache: tt.fields.puidCache,
				podCache:  tt.fields.podCache,
			}
			c.deletePUIDEntry(tt.args.puid)

			if got := tt.fields.puidCache; !reflect.DeepEqual(got, tt.want1) {
				t.Errorf("after cache.deleteByPod = %v, want %v", got, tt.want1)
			}
			if got := tt.fields.podCache; !reflect.DeepEqual(got, tt.want2) {
				t.Errorf("after cache.deleteByPod = %v, want %v", got, tt.want2)
			}

		})
	}
}

func Test_cache_deletePUIDCache(t *testing.T) {

	puid1 := "12349"
	pod1 := "test/test4"
	containerRuntime := policy.NewPURuntimeWithDefaults()
	containerRuntime.SetPid(123)
	puidEntry1 := &puidCacheEntry{
		kubeIdentifier:    pod1,
		kubernetesRuntime: containerRuntime,
	}
	podEntry1 := &podCacheEntry{
		puIDs: map[string]bool{
			puid1: true,
		},
	}

	type fields struct {
		puidCache map[string]*puidCacheEntry
		podCache  map[string]*podCacheEntry
		RWMutex   sync.RWMutex
	}
	type args struct {
		puID string
	}
	tests := []struct {
		name   string
		fields *fields
		args   *args
		want1  map[string]*puidCacheEntry
		want2  map[string]*podCacheEntry
	}{
		{
			name:   "Delete on empty cache",
			fields: &fields{},
			args: &args{
				puID: "1234",
			},
			want1: nil,
			want2: nil,
		},
		{
			name: "Deleting a non existent puid",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{
					puid1: puidEntry1,
				},
				podCache: map[string]*podCacheEntry{
					pod1: podEntry1,
				},
			},
			args: &args{
				puID: "1234",
			},
			want1: map[string]*puidCacheEntry{
				puid1: puidEntry1,
			},
			want2: map[string]*podCacheEntry{
				pod1: podEntry1,
			},
		},
		{
			name: "Normal case",
			fields: &fields{
				puidCache: map[string]*puidCacheEntry{
					puid1: puidEntry1,
				},
				podCache: map[string]*podCacheEntry{
					pod1: podEntry1,
				},
			},
			args: &args{
				puID: "12349",
			},
			want1: map[string]*puidCacheEntry{},
			want2: map[string]*podCacheEntry{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &cache{
				puidCache: tt.fields.puidCache,
				podCache:  tt.fields.podCache,
			}
			c.deletePUIDCache(tt.args.puID)
			if got := tt.fields.puidCache; !reflect.DeepEqual(got, tt.want1) {
				t.Errorf("after cache.deleteByPod = %v, want %v", got, tt.want1)
			}
			if got := tt.fields.podCache; !reflect.DeepEqual(got, tt.want2) {
				t.Errorf("after cache.deleteByPod = %v, want %v", got, tt.want2)
			}
		})
	}
}
