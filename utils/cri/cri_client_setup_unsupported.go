// +build !linux,!windows

package cri

import (
	"context"
	"errors"
)

// NewCRIRuntimeServiceClient is not supported for non-linux
func NewCRIRuntimeServiceClient(ctx context.Context, criRuntimeEndpoint string) (ExtendedRuntimeService, error) {
	return nil, errors.New("unsupported platform")
}

// DetectCRIRuntimeEndpoint checks if the unix socket path are present for CRI
func DetectCRIRuntimeEndpoint() (string, Type, error) {
	return "", TypeNone, errors.New("unsupported platform")
}
