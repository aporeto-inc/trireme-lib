package k8smonitor

import (
	"context"
	"sync"
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.uber.org/zap"
)

var (
	// defaultLoopWait defines how often we loop over the entries to discover dead containers
	defaultLoopWait = time.Second * 5
)

type runtimeCacheInterface interface {
	Delete(sandboxID string)
	Get(sandboxID string) policy.RuntimeReader
	Set(sandboxID string, runtime policy.RuntimeReader) error
}

var _ runtimeCacheInterface = &runtimeCache{}

type runtimeCache struct {
	sync.RWMutex
	runtimes  map[string]runtimeCacheEntry
	loopWait  time.Duration
	stopEvent stopEventFunc
}

type runtimeCacheEntry struct {
	runtime policy.RuntimeReader
	running bool
}

func newRuntimeCache(ctx context.Context, stopEvent stopEventFunc) *runtimeCache {
	c := &runtimeCache{
		runtimes:  make(map[string]runtimeCacheEntry),
		loopWait:  defaultLoopWait,
		stopEvent: stopEvent,
	}
	if c.loopWait > 0 {
		go c.loop(ctx)
	}
	return c
}

func makeSnapshot(m map[string]runtimeCacheEntry) map[string]policy.RuntimeReader {
	snap := make(map[string]policy.RuntimeReader, len(m))
	for k, v := range m {
		if v.running {
			snap[k] = v.runtime
		}
	}
	return snap
}

// loop is very awkward: it implements a runtime poller that checks if all runtimes
// are actually still running. If not, it sends a stop event.
// NOTE: this must be deprecated once we have hooked into the OCI runtime hooks in the bundle!
func (c *runtimeCache) loop(ctx context.Context) {
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-time.After(c.loopWait):
			c.RLock()
			if len(c.runtimes) > 0 {
				// take a snapshot
				snap := makeSnapshot(c.runtimes)
				c.RUnlock()
				// and process them
				c.processRuntimes(ctx, snap)
			} else {
				c.RUnlock()
			}
		}
	}
}

// processRuntimes takes a snapshot of the runtimeCache, checks if the process is running, and sends a stop event if not
func (c *runtimeCache) processRuntimes(ctx context.Context, snap map[string]policy.RuntimeReader) {
	for id, runtime := range snap {
		pid := runtime.Pid()
		if pid > 0 {
			if running, err := sandboxIsRunning(pid); !running {
				// if there has been error checking, just continue
				if err != nil {
					zap.L().Error("K8sMonitor: runtime poller: failed to check if sandbox is still running",
						zap.String("sandboxID", id),
						zap.Int("sandboxPid", pid),
						zap.Error(err),
					)
					continue
				}
				zap.L().Debug("K8sMonitor: runtime poller: sandbox container must have stopped", zap.String("sandboxID", id), zap.Int("sandboxPid", pid), zap.Error(err))

				// update the entry
				c.Lock()
				if _, ok := c.runtimes[id]; ok {
					c.runtimes[id] = runtimeCacheEntry{
						runtime: runtime,
						running: false,
					}
				}
				c.Unlock()

				// fire away a stop event to the policy engine
				// log an error as every caller should do, but continue normally
				// there is nothing we can do about the error
				go func(ctx context.Context, sandboxID string) {
					if err := c.stopEvent(ctx, sandboxID); err != nil {
						zap.L().Error("K8sMonitor: runtime poller: failed to send stop event to policy engine", zap.String("sandboxID", sandboxID), zap.Error(err))
					}
				}(ctx, id)
			}
		}
	}
}

func (c *runtimeCache) Get(sandboxID string) policy.RuntimeReader {
	if c == nil {
		return nil
	}
	c.RLock()
	defer c.RUnlock()
	if c.runtimes == nil {
		return nil
	}
	r, ok := c.runtimes[sandboxID]
	if !ok {
		return nil
	}
	// TODO: should return a clone, not a pointer
	return r.runtime
}

func (c *runtimeCache) Set(sandboxID string, runtime policy.RuntimeReader) error {
	if c == nil {
		return errCacheUninitialized
	}
	if sandboxID == "" {
		return errSandboxEmpty
	}
	if runtime == nil {
		return errRuntimeNil
	}
	c.Lock()
	defer c.Unlock()
	if c.runtimes == nil {
		return errCacheUninitialized
	}
	c.runtimes[sandboxID] = runtimeCacheEntry{
		runtime: runtime,
		running: true,
	}
	return nil
}

func (c *runtimeCache) Delete(sandboxID string) {
	if c == nil {
		return
	}
	c.Lock()
	defer c.Unlock()
	delete(c.runtimes, sandboxID)
}
