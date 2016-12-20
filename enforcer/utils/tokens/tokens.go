package tokens

import "github.com/aporeto-inc/trireme/policy"

// ConnectionClaims captures all the claim information
type ConnectionClaims struct {
	T   *policy.TagsMap
	LCL []byte
	RMT []byte
	EK  []byte
}

// TokenEngine is the interface to the different implementations of tokens
type TokenEngine interface {
	// CreteAndSign creates a token, signs it and produces the final byte string
	CreateAndSign(attachCert bool, claims *ConnectionClaims) []byte
	// Decode decodes an incoming buffer and returns the claims and the sender certificate
	Decode(decodeCert bool, buffer []byte, cert interface{}) (*ConnectionClaims, interface{})
}

// SecretsType identifies the different secrets that are supported
type SecretsType int

const (
	// PKIType  for assymetric signing
	PKIType SecretsType = iota
	// PSKType  for symetric signing
	PSKType
)

const (
	// MaxServerName must be of UUID size maximum
	MaxServerName = 36
)

// Secrets is an interface implementing Secrets
type Secrets interface {
	Type() SecretsType
	EncodingKey() interface{}
	DecodingKey(server string, ackCert, prevCert interface{}) (interface{}, error)
	TransmittedKey() []byte
	VerifyPublicKey(pkey []byte) (interface{}, error)
	AckSize() uint32
}
