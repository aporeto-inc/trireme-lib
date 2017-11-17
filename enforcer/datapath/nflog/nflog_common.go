package nflog

import (
	"github.com/aporeto-inc/trireme-lib/policy"
)

// NFLogger provides an interface for NFLog
type NFLogger interface {
	start()
	stop()
}

type puInfoFunc func(string) (string, *policy.TagStore)
