package secrets

import "fmt"

// Secrets is an interface implementing secrets
type Secrets interface {
	// Type must return the type of the secrets as defined in the PrivateSecretsType
	Type() PrivateSecretsType
	// EncodingKey returns the key used to encode the tokens.
	EncodingKey() interface{}
	// DecodingKey is the key used to decode the tokens.
	DecodingKey(server string, ackCert, prevCert interface{}) (interface{}, error)
	// PublicKey returns the public ket of the secrets.
	PublicKey() interface{}
	// TransmittedKey returns the public key as a byte slice and as it is transmitted
	// on the wire.
	TransmittedKey() []byte
	// VerifyPublicKey will verify a public key and whether it is signed by a trusted
	// authority.
	VerifyPublicKey(pkey []byte) (interface{}, error)
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
	// PKIType  for asymmetric signing
	PKIType PrivateSecretsType = iota
	// PSKType  for symetric signing
	PSKType
	// PKICompactType is for asymetric signing using compact JWTs on the wire
	PKICompactType
	// PKINull is for debugging
	PKINull
)

// NewSecrets creates a new set of secrets based on the type.
func NewSecrets(s PublicSecrets) (Secrets, error) {
	switch s.SecretsType() {
	case PKIType:
		t := s.(*PKIPublicSecrets)
		return NewPKISecrets(t.Key, t.Certificate, t.CA, nil)
	case PKICompactType:
		t := s.(*CompactPKIPublicSecrets)
		return NewCompactPKIWithTokenCA(t.Key, t.Certificate, t.CA, t.TokenCAs, t.Token, t.Compressed)
	case PSKType:
		t := s.(*PSKPublicSecrets)
		return NewPSKSecrets(t.SharedKey), nil
	default:
		return nil, fmt.Errorf("Unsupported type")
	}
}
