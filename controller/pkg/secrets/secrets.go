package secrets

import (
	"fmt"
	"time"
)

// LockedSecrets provides a way to use secrets where shared read access is required. The user becomes responsible for unlocking when done using them.
// The implementation should lock the access to secrets for reading, and pass down the function for unlocking.
type LockedSecrets interface {
	Secrets() (Secrets, func())
}

// Secrets is an interface implementing secrets
type Secrets interface {
	// Type must return the type of the secrets as defined in the PrivateSecretsType
	Type() PrivateSecretsType
	// EncodingKey returns the key used to encode the tokens.
	EncodingKey() interface{}
	// PublicKey returns the public ket of the secrets.
	PublicKey() interface{}
	// TransmittedKey returns the public key as a byte slice and as it is transmitted
	// on the wire.
	TransmittedKey() []byte
	// KeyAndClaims will verify the public key and return any claims that are part of the key.
	KeyAndClaims(pkey []byte) (interface{}, []string, time.Time, error)
	// AckSize calculates the size of the ACK packet based on the keys.
	AckSize() uint32
	// PublicSecrets returns the PEM formated secrets to be transmitted over the RPC interface.
	PublicSecrets() PublicSecrets
}

// PublicSecrets is an interface of the data structures of the secrets
// that can be transmitted over the RPC interface to the remotes.
type PublicSecrets interface {
	SecretsType() PrivateSecretsType
	CertAuthority() []byte
}

// PrivateSecretsType identifies the different secrets that are supported
type PrivateSecretsType int

const (
	// PKICompactType is for asymetric signing using compact JWTs on the wire
	PKICompactType PrivateSecretsType = iota
	// PKINull is for debugging
	PKINull
)

// NewSecrets creates a new set of secrets based on the type.
func NewSecrets(s PublicSecrets) (Secrets, error) {
	switch s.SecretsType() {
	case PKICompactType:
		t := s.(*CompactPKIPublicSecrets)
		return NewCompactPKIWithTokenCA(t.Key, t.Certificate, t.CA, t.TokenCAs, t.Token, t.Compressed)
	default:
		return nil, fmt.Errorf("Unsupported type")
	}
}
