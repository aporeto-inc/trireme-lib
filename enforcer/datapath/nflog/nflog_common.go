package nflog

import (
	"github.com/aporeto-inc/trireme-lib/policy"
)

// NFLogger provides an interface for NFLog
type NFLogger interface {
	Start()
	Stop()
}

// GetPUInfoFunc provides PU information given the id
type GetPUInfoFunc func(id string) (string, *policy.TagStore)
