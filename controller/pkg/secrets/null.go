package secrets

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// This is a NULL secrets implementation only for performance testing
// ATTENTION *** ONLY FOR TESTING
// DO NOT USE FOR ANY REAL CODE

// NullPKI holds all PKI information
type NullPKI struct {
	PrivateKeyPEM []byte
	PublicKeyPEM  []byte
	AuthorityPEM  []byte
}

// NewNullPKI creates new secrets for PKI implementation based on compact encoding
func NewNullPKI(keyPEM, certPEM, caPEM []byte) (*NullPKI, error) {

	p := &NullPKI{}
	return p, nil
}

// Type implements the interface Secrets
func (p *NullPKI) Type() PrivateSecretsType {
	return PKINull
}

// EncodingKey returns the private key
func (p *NullPKI) EncodingKey() interface{} {
	return jwt.UnsafeAllowNoneSignatureType
}

// PublicKey returns nil in this case
func (p *NullPKI) PublicKey() interface{} {
	return nil
}

//KeyAndClaims returns both the key and any attributes associated with the public key.
func (p *NullPKI) KeyAndClaims(pkey []byte) (interface{}, []string, time.Time, error) {
	return jwt.UnsafeAllowNoneSignatureType, []string{}, time.Now(), nil
}

// TransmittedKey returns the PEM of the public key in the case of PKI
// if there is no certificate cache configured
func (p *NullPKI) TransmittedKey() []byte {
	return []byte("none")
}

// AckSize returns the default size of an ACK packet
func (p *NullPKI) AckSize() uint32 {
	return uint32(235)
}

// PublicSecrets returns the secrets that are marshallable over the RPC interface.
func (p *NullPKI) PublicSecrets() PublicSecrets {
	return &NullPublicSecrets{
		Type: PKINull,
	}
}

// NullPublicSecrets includes all the secrets that can be transmitted over
// the RPC interface.
type NullPublicSecrets struct {
	Type PrivateSecretsType
}

// SecretsType returns the type of secrets.
func (p *NullPublicSecrets) SecretsType() PrivateSecretsType {
	return p.Type
}

// CertAuthority returns the cert authority - N/A to PSK
func (p *NullPublicSecrets) CertAuthority() []byte {
	return []byte{}
}
