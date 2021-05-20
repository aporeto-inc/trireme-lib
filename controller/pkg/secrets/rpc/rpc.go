package rpc

import (
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets/compactpki"
)

// NewSecrets creates a new set of secrets based on the RPCSecrets.
// We support only one type for now, CompactPKI.
func NewSecrets(r secrets.RPCSecrets) (secrets.Secrets, error) {
	return compactpki.NewCompactPKIWithTokenCA(r.Key, r.Certificate, r.CA, r.TrustedControllers, r.Token, r.Compressed)
}
