package panicrecovery

import (
	"runtime/debug"

	"go.uber.org/zap"
)

// HandleEventualPanic recovers panic from a goroutine.
// prints the stack trace.
func HandleEventualPanic(source string) {

	if r := recover(); r == nil {
		return
	}

	zap.L().Error("Panic in ", zap.String("source", source))
	st := string(debug.Stack())
	zap.L().Error("panic", zap.String("stacktrace", st))

	return
}
