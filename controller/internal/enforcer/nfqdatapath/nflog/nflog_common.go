package nflog

import (
	"context"

	"go.aporeto.io/trireme-lib/policy"
)

// NFLogger provides an interface for NFLog
type NFLogger interface {
	Run(ctx context.Context)
}

// GetPUInfoFunc provides PU information given the id
type GetPUInfoFunc func(id string) (string, string, *policy.TagStore)
