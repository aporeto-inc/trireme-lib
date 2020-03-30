// +build windows

package secretsproxy

import (
	"context"

	"go.aporeto.io/trireme-lib/v11/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/v11/policy"
)

// SecretsProxy holds all state information for applying policy
// in the secrets socket API.
type SecretsProxy struct {
}

// NewSecretsProxy creates a new secrets proxy.
func NewSecretsProxy() *SecretsProxy {
	return &SecretsProxy{}
}

// Run implements the run method of the CtrlInterface. It starts the proxy
// server and initializes the data structures.
func (s *SecretsProxy) Run(ctx context.Context) error {
	return nil
}

// Enforce implements the corresponding interface of enforcers.
func (s *SecretsProxy) Enforce(puInfo *policy.PUInfo) error {
	return nil
}

// Unenforce implements the corresponding interface of the enforcers.
func (s *SecretsProxy) Unenforce(contextID string) error {
	return nil
}

// GetFilterQueue is a stub for TCP proxy
func (s *SecretsProxy) GetFilterQueue() *fqconfig.FilterQueue {
	return nil
}

// UpdateSecrets updates the secrets of running enforcers managed by trireme. Remote enforcers will
// get the secret updates with the next policy push.
func (s *SecretsProxy) UpdateSecrets(secret secrets.Secrets) error {
	return nil
}
