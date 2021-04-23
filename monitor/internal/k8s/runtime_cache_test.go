// +build linux

package k8smonitor

// TODO: make compatible with Windows

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

func Test_runtimeCache_Delete(t *testing.T) {
	stopEvent := func(context.Context, string) error {
		return nil
	}

	// override globals for unit tests
	oldDefaultLoopWait := defaultLoopWait
	oldSyscallKill := syscallKill
	defer func() {
		defaultLoopWait = oldDefaultLoopWait
		syscallKill = oldSyscallKill
	}()
	defaultLoopWait = time.Duration(0)
	syscallKill = func(int, syscall.Signal) (err error) {
		return nil
	}

	tests := []struct {
		name      string
		c         *runtimeCache
		sandboxID string
	}{
		{
			name:      "cache uninitialized",
			c:         nil,
			sandboxID: "does-not-matter",
		},
		{
			name:      "cache initialized",
			c:         newRuntimeCache(context.TODO(), stopEvent),
			sandboxID: "does-not-mater",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.c.Delete(tt.sandboxID)
		})
	}
}

func Test_runtimeCache_Set(t *testing.T) {
	stopEvent := func(context.Context, string) error {
		return nil
	}

	// override globals for unit tests
	oldDefaultLoopWait := defaultLoopWait
	oldSyscallKill := syscallKill
	defer func() {
		defaultLoopWait = oldDefaultLoopWait
		syscallKill = oldSyscallKill
	}()
	defaultLoopWait = time.Duration(0)
	syscallKill = func(int, syscall.Signal) (err error) {
		return nil
	}

	type args struct {
		sandboxID string
		runtime   policy.RuntimeReader
	}
	tests := []struct {
		name         string
		c            *runtimeCache
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
			c:            &runtimeCache{},
			wantErr:      true,
			wantErrError: errCacheUninitialized,
			args: args{
				sandboxID: "does-not-matter",
				runtime:   policy.NewPURuntimeWithDefaults(),
			},
		},
		{
			name:         "no sandboxID",
			c:            newRuntimeCache(context.TODO(), stopEvent),
			wantErr:      true,
			wantErrError: errSandboxEmpty,
			args: args{
				sandboxID: "",
				runtime:   policy.NewPURuntimeWithDefaults(),
			},
		},
		{
			name:         "runtime is nil",
			c:            newRuntimeCache(context.TODO(), stopEvent),
			wantErr:      true,
			wantErrError: errRuntimeNil,
			args: args{
				sandboxID: "does-not-matter",
				runtime:   nil,
			},
		},
		{
			name:    "successful update entry",
			c:       newRuntimeCache(context.TODO(), stopEvent),
			wantErr: false,
			args: args{
				sandboxID: "does-not-matter",
				runtime:   policy.NewPURuntimeWithDefaults(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.c.Set(tt.args.sandboxID, tt.args.runtime)
			if (err != nil) != tt.wantErr {
				t.Errorf("runtimeCache.Set() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if err != tt.wantErrError {
					t.Errorf("runtimeCache.Set() error = %v, wantErrError %v", err, tt.wantErrError)
				}
			}
		})
	}
}

func Test_runtimeCache_Get(t *testing.T) {
	stopEvent := func(context.Context, string) error {
		return nil
	}

	// override globals for unit tests
	oldDefaultLoopWait := defaultLoopWait
	oldSyscallKill := syscallKill
	defer func() {
		defaultLoopWait = oldDefaultLoopWait
		syscallKill = oldSyscallKill
	}()
	defaultLoopWait = time.Duration(0)
	syscallKill = func(int, syscall.Signal) (err error) {
		return nil
	}

	cacheWithEntry := newRuntimeCache(context.TODO(), stopEvent)
	if err := cacheWithEntry.Set("entry", policy.NewPURuntimeWithDefaults()); err != nil {
		panic(err)
	}
	tests := []struct {
		name      string
		sandboxID string
		c         *runtimeCache
		want      policy.RuntimeReader
	}{
		{
			name: "uninitialized runtimeCache",
			c:    nil,
			want: nil,
		},
		{
			name: "uninitialized map in runtimeCache",
			c:    &runtimeCache{},
			want: nil,
		},
		{
			name:      "entry does not exist",
			c:         newRuntimeCache(context.TODO(), stopEvent),
			sandboxID: "does-not-exist",
			want:      nil,
		},
		{
			name:      "entry exists",
			c:         cacheWithEntry,
			sandboxID: "entry",
			want:      policy.NewPURuntimeWithDefaults(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.Get(tt.sandboxID); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("runtimeCache.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_makeSnapshot(t *testing.T) {
	type args struct {
		m map[string]runtimeCacheEntry
	}
	tests := []struct {
		name string
		args args
		want map[string]policy.RuntimeReader
	}{
		{
			name: "empty",
			args: args{
				m: map[string]runtimeCacheEntry{},
			},
			want: map[string]policy.RuntimeReader{},
		},
		{
			name: "not-running entry",
			args: args{
				m: map[string]runtimeCacheEntry{
					"entry": {
						runtime: policy.NewPURuntimeWithDefaults(),
						running: false,
					},
				},
			},
			want: map[string]policy.RuntimeReader{},
		},
		{
			name: "running entry",
			args: args{
				m: map[string]runtimeCacheEntry{
					"entry": {
						runtime: policy.NewPURuntimeWithDefaults(),
						running: true,
					},
				},
			},
			want: map[string]policy.RuntimeReader{
				"entry": policy.NewPURuntimeWithDefaults(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := makeSnapshot(tt.args.m); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("makeSnapshot() = %v, want %v", got, tt.want)
			}
		})
	}
}

type unitTestStopEvent interface {
	f() stopEventFunc
	wait()
	called() bool
}
type unitTestStopEventHandler struct {
	sync.RWMutex
	wg        sync.WaitGroup
	wgCounter int
	wasCalled bool
	err       error
}

func (h *unitTestStopEventHandler) stopEvent(context.Context, string) error {
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

func (h *unitTestStopEventHandler) f() stopEventFunc {
	return h.stopEvent
}

func (h *unitTestStopEventHandler) wait() {
	h.wg.Wait()
}

func (h *unitTestStopEventHandler) called() bool {
	h.RLock()
	defer h.RUnlock()
	return h.wasCalled
}

func newUnitTestStopEventHandler(n int, err error) unitTestStopEvent {
	h := &unitTestStopEventHandler{
		err:       err,
		wgCounter: n,
	}
	h.wg.Add(n)
	return h
}

func Test_runtimeCache_processRuntimes(t *testing.T) {
	// override globals for unit tests
	oldDefaultLoopWait := defaultLoopWait
	oldSyscallKill := syscallKill
	defer func() {
		defaultLoopWait = oldDefaultLoopWait
		syscallKill = oldSyscallKill
	}()
	defaultLoopWait = time.Duration(0)
	syscallKill = func(int, syscall.Signal) (err error) {
		return nil
	}

	type fields struct {
		runtimes map[string]runtimeCacheEntry
	}
	type args struct {
		ctx  context.Context
		snap map[string]policy.RuntimeReader
	}

	runtime := policy.NewPURuntime("entry", 42, "", nil, nil, common.ContainerPU, policy.None, nil)
	tests := []struct {
		name              string
		syscallKill       func(int, syscall.Signal) error
		stopEventHandler  unitTestStopEvent
		fields            fields
		args              args
		expectedStopEvent bool
		expectedRuntimes  map[string]runtimeCacheEntry
	}{
		{
			name: "process still running",
			syscallKill: func(int, syscall.Signal) error {
				return nil
			},
			stopEventHandler: newUnitTestStopEventHandler(0, nil),
			fields: fields{
				runtimes: map[string]runtimeCacheEntry{
					"entry": {
						runtime: runtime,
						running: true,
					},
				},
			},
			args: args{
				ctx: context.Background(),
				snap: map[string]policy.RuntimeReader{
					"entry": runtime,
				},
			},
			expectedStopEvent: false,
			expectedRuntimes: map[string]runtimeCacheEntry{
				"entry": {
					runtime: runtime,
					running: true,
				},
			},
		},
		{
			name: "syscall returns unexpected error",
			syscallKill: func(int, syscall.Signal) error {
				return fmt.Errorf("unexpected error")
			},
			stopEventHandler: newUnitTestStopEventHandler(0, nil),
			fields: fields{
				runtimes: map[string]runtimeCacheEntry{
					"entry": {
						runtime: runtime,
						running: true,
					},
				},
			},
			args: args{
				ctx: context.Background(),
				snap: map[string]policy.RuntimeReader{
					"entry": runtime,
				},
			},
			expectedStopEvent: false,
			expectedRuntimes: map[string]runtimeCacheEntry{
				"entry": {
					runtime: runtime,
					running: true,
				},
			},
		},
		{
			name: "process not running anymore",
			syscallKill: func(int, syscall.Signal) error {
				return syscall.ESRCH
			},
			stopEventHandler: newUnitTestStopEventHandler(1, fmt.Errorf("more test coverage")),
			fields: fields{
				runtimes: map[string]runtimeCacheEntry{
					"entry": {
						runtime: runtime,
						running: true,
					},
				},
			},
			args: args{
				ctx: context.Background(),
				snap: map[string]policy.RuntimeReader{
					"entry": runtime,
				},
			},
			expectedStopEvent: true,
			expectedRuntimes: map[string]runtimeCacheEntry{
				"entry": {
					runtime: runtime,
					running: false,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			syscallKill = tt.syscallKill
			c := &runtimeCache{
				runtimes:  tt.fields.runtimes,
				stopEvent: tt.stopEventHandler.f(),
			}
			ctx, cancel := context.WithCancel(tt.args.ctx)
			defer cancel()
			c.processRuntimes(ctx, tt.args.snap)
			tt.stopEventHandler.wait()
			if !reflect.DeepEqual(c.runtimes, tt.expectedRuntimes) {
				t.Errorf("c.runtimes = %v, want %v", c.runtimes, tt.expectedRuntimes)
			}
			if tt.expectedStopEvent != tt.stopEventHandler.called() {
				t.Errorf("stopEventHandler.called() = %v, want %v", tt.stopEventHandler.called(), tt.expectedStopEvent)
			}
		})
	}
}

func Test_runtimeCache_loop(t *testing.T) {
	stopEventHandler := newUnitTestStopEventHandler(1, nil)

	// override globals for unit tests
	oldDefaultLoopWait := defaultLoopWait
	oldSyscallKill := syscallKill
	defer func() {
		defaultLoopWait = oldDefaultLoopWait
		syscallKill = oldSyscallKill
	}()
	defaultLoopWait = time.Duration(1)
	syscallKill = func(int, syscall.Signal) error {
		return syscall.ESRCH
	}

	tests := []struct {
		name             string
		stopEventHandler unitTestStopEvent
	}{
		{
			name:             "successful loop",
			stopEventHandler: stopEventHandler,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// this starts the loop already
			ctx, cancel := context.WithCancel(context.Background())
			c := newRuntimeCache(ctx, tt.stopEventHandler.f())

			// TODO: to get that last inch of coverage :) not sure how else to get that
			time.Sleep(time.Millisecond * 10)

			// add a runtime
			runtime := policy.NewPURuntime("entry", 42, "", nil, nil, common.ContainerPU, policy.None, nil)
			c.Set("entry", runtime) // nolint: errcheck
			c.RLock()
			if c.runtimes["entry"].running != true { // nolint
				t.Errorf("entry is not marked as running")
			}
			c.RUnlock()

			// wait until the stop event was called
			tt.stopEventHandler.wait()
			cancel()

			c.RLock()
			if c.runtimes["entry"].running != false { // nolint
				t.Errorf("entry is still marked as running")
			}
			c.RUnlock()
		})
	}
}
