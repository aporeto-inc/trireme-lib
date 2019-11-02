package nflog

import (
	"context"

	"go.aporeto.io/trireme-lib/v11/controller/pkg/pucontext"
)

// NFLogger provides an interface for NFLog
type NFLogger interface {
	Run(ctx context.Context)
}

// GetPUContextFunc provides PU information given the id
type GetPUContextFunc func(hash string) (*pucontext.PUContext, error)
