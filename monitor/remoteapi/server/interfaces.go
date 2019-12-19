package server

import (
	"context"
)

// APIServer is the main interface of the API server.
// Allows to create mock functions for testing.
type APIServer interface {
	// Run runs an API server
	Run(ctx context.Context) error
}
