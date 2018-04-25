package panicrecovery

import (
	"context"
	"os"
	"os/exec"
	"runtime/debug"
	"time"

	"go.uber.org/zap"
)

// HandleEventualPanic recovers panic from a goroutine.
// prints the stack trace.
func HandleEventualPanic(source string, cancel context.CancelFunc) {

	if r := recover(); r == nil {
		return
	}

	if cancel != nil {
		// cancel other go routines
		cancel()
	}

	zap.L().Info("Cleaning up iptables")
	cmd := exec.Command("iptables", "-t", "mangle", "-F")
	if err := cmd.Run(); err != nil {
		zap.L().Error("Failed to delete rules", zap.Error(err))
	}

	// needed for flush to complete
	time.Sleep(2 * time.Second)
	cmd = exec.Command("iptables", "-t", "mangle", "-X")
	if err := cmd.Run(); err != nil {
		zap.L().Error("Failed to flush chains", zap.Error(err))
	}

	cmd = exec.Command("ipset", "destroy")
	if err := cmd.Run(); err != nil {
		zap.L().Error("Failed to flush IP tables", zap.Error(err))
	}
	zap.L().Error("Panic in ", zap.String("source", source))
	st := string(debug.Stack())
	zap.L().Error("panic", zap.String("stacktrace", st))

	os.Exit(-1)
}
