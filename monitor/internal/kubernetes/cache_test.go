package kubernetesmonitor

import (
	"reflect"
	"sync"
	"testing"

	"github.com/aporeto-inc/trireme-lib/policy"
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
	type fieldsResult struct {
		puidCache map[string]*puidCacheEntry
		podCache  map[string]*podCacheEntry
		RWMutex   sync.RWMutex
	}
	tests := []struct {
		name         string
		fields       fields
		fieldsResult fields
		args         args
	}{
		{
			name: "test empty all",
			fields: fields{
				puidCache: map[string]*puidCacheEntry{},
				podCache:  map[string]*podCacheEntry{},
			},
			fieldsResult: fields{
				puidCache: map[string]*puidCacheEntry{},
				podCache:  map[string]*podCacheEntry{},
			},
			args: args{
				podNamespace:      "",
				podName:           "",
				puID:              "",
				dockerRuntime:     policy.NewPURuntimeWithDefaults(),
				kubernetesRuntime: policy.NewPURuntimeWithDefaults(),
			},
		},
		{
			name: "test empty NS",
			fields: fields{
				puidCache: map[string]*puidCacheEntry{},
				podCache:  map[string]*podCacheEntry{},
			},
			fieldsResult: fields{
				puidCache: map[string]*puidCacheEntry{},
				podCache:  map[string]*podCacheEntry{},
			},
			args: args{
				podNamespace:      "",
				podName:           "xcvxcv",
				puID:              "xcvxcv",
				dockerRuntime:     policy.NewPURuntimeWithDefaults(),
				kubernetesRuntime: policy.NewPURuntimeWithDefaults(),
			},
		},
		{
			name: "test empty Name",
			fields: fields{
				puidCache: map[string]*puidCacheEntry{},
				podCache:  map[string]*podCacheEntry{},
			},
			fieldsResult: fields{
				puidCache: map[string]*puidCacheEntry{},
				podCache:  map[string]*podCacheEntry{},
			},
			args: args{
				podNamespace:      "xcvxcv",
				podName:           "",
				puID:              "xcvxcv",
				dockerRuntime:     policy.NewPURuntimeWithDefaults(),
				kubernetesRuntime: policy.NewPURuntimeWithDefaults(),
			},
		},
		{
			name: "test empty PUID",
			fields: fields{
				puidCache: map[string]*puidCacheEntry{},
				podCache:  map[string]*podCacheEntry{},
			},
			fieldsResult: fields{
				puidCache: map[string]*puidCacheEntry{},
				podCache:  map[string]*podCacheEntry{},
			},
			args: args{
				podNamespace:      "xcvxcv",
				podName:           "xcvxcv",
				puID:              "",
				dockerRuntime:     policy.NewPURuntimeWithDefaults(),
				kubernetesRuntime: policy.NewPURuntimeWithDefaults(),
			},
		},
		{
			name: "test normal behavior",
			fields: fields{
				puidCache: map[string]*puidCacheEntry{},
				podCache:  map[string]*podCacheEntry{},
			},
			fieldsResult: fields{
				puidCache: map[string]*puidCacheEntry{
					"123456": &puidCacheEntry{
						kubeIdentifier:    "namespace/name",
						dockerRuntime:     runtime1,
						kubernetesRuntime: runtime2,
					},
				},
				podCache: map[string]*podCacheEntry{
					"namespace/name": &podCacheEntry{
						puIDs: map[string]bool{
							"123456": true,
						},
					},
				},
			},
			args: args{
				podNamespace:      "namespace",
				podName:           "name",
				puID:              "123456",
				dockerRuntime:     runtime1,
				kubernetesRuntime: runtime2,
			},
		},
		{
			name: "test additive behavior",
			fields: fields{
				puidCache: map[string]*puidCacheEntry{
					"123456": &puidCacheEntry{
						kubeIdentifier:    "namespace/name",
						dockerRuntime:     runtime1,
						kubernetesRuntime: runtime2,
					},
				},
				podCache: map[string]*podCacheEntry{
					"namespace/name": &podCacheEntry{
						puIDs: map[string]bool{
							"123456": true,
						},
					},
				},
			},
			fieldsResult: fields{
				puidCache: map[string]*puidCacheEntry{
					"123456": &puidCacheEntry{
						kubeIdentifier:    "namespace/name",
						dockerRuntime:     runtime1,
						kubernetesRuntime: runtime2,
					},
					"abcdef": &puidCacheEntry{
						kubeIdentifier:    "namespace2/name2",
						dockerRuntime:     runtime3,
						kubernetesRuntime: runtime2,
					},
				},
				podCache: map[string]*podCacheEntry{
					"namespace/name": &podCacheEntry{
						puIDs: map[string]bool{
							"123456": true,
						},
					},
					"namespace2/name2": &podCacheEntry{
						puIDs: map[string]bool{
							"abcdef": true,
						},
					},
				},
			},
			args: args{
				podNamespace:      "namespace2",
				podName:           "name2",
				puID:              "abcdef",
				dockerRuntime:     runtime3,
				kubernetesRuntime: runtime2,
			},
		},
		{
			name: "test additive same pod",
			fields: fields{
				puidCache: map[string]*puidCacheEntry{
					"123456": &puidCacheEntry{
						kubeIdentifier:    "namespace/name",
						dockerRuntime:     runtime1,
						kubernetesRuntime: runtime2,
					},
				},
				podCache: map[string]*podCacheEntry{
					"namespace/name": &podCacheEntry{
						puIDs: map[string]bool{
							"123456": true,
						},
					},
				},
			},
			fieldsResult: fields{
				puidCache: map[string]*puidCacheEntry{
					"123456": &puidCacheEntry{
						kubeIdentifier:    "namespace/name",
						dockerRuntime:     runtime1,
						kubernetesRuntime: runtime2,
					},
					"abcdef": &puidCacheEntry{
						kubeIdentifier:    "namespace/name",
						dockerRuntime:     runtime3,
						kubernetesRuntime: runtime2,
					},
				},
				podCache: map[string]*podCacheEntry{
					"namespace/name": &podCacheEntry{
						puIDs: map[string]bool{
							"123456": true,
							"abcdef": true,
						},
					},
				},
			},
			args: args{
				podNamespace:      "namespace",
				podName:           "name",
				puID:              "abcdef",
				dockerRuntime:     runtime3,
				kubernetesRuntime: runtime2,
			},
		},
	}
	for _, tt := range tests { // nolint
		t.Run(tt.name, func(t *testing.T) { // nolint
			c := &cache{ // nolint
				puidCache: tt.fields.puidCache, // nolint
				podCache:  tt.fields.podCache,  // nolint
				RWMutex:   tt.fields.RWMutex,   // nolint
			} // nolint
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
