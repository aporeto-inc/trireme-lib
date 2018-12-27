package tokens

import "go.aporeto.io/trireme-lib/policy"

// ConnectionClaims captures all the claim information
type ConnectionClaims struct {
	T *policy.TagStore `json:",omitempty"`
	// RMT is the nonce of the remote that has to be signed in the JWT
	RMT []byte `json:",omitempty"`
	// LCL is the nonce of the local node that has to be signed
	LCL []byte `json:",omitempty"`
	// EK is the ephemeral EC key for encryption
	EK []byte `json:",omitempty"`
	// C is the compressed tags in one string
	C string `json:",omitempty"`
	// ID is the source PU ID
	ID string `json:",omitempty"`
	// V is the version of the enforcer
	V []byte `json:",omitempty"`
}

// TokenEngine is the interface to the different implementations of tokens
type TokenEngine interface {
	// CreteAndSign creates a token, signs it and produces the final byte string
	CreateAndSign(isAck bool, claims *ConnectionClaims, nonce []byte) (token []byte, err error)
	// Decode decodes an incoming buffer and returns the claims and the sender certificate
	Decode(isAck bool, data []byte, previousCert interface{}) (claims *ConnectionClaims, nonce []byte, publicKey interface{}, err error)
	// Randomize inserts a source nonce in an existing token - New nonce will be
	// create every time the token is transmitted as a challenge to the other side
	// even when the token is cached. There should be space in the token already.
	// Returns an error if there is no space
	Randomize([]byte, []byte) (err error)
	// RetrieveNonce retrieves the nonce from the token only. Returns the nonce
	// or an error if the nonce cannot be decoded
	RetrieveNonce([]byte) ([]byte, error)
}

const (
	// MaxServerName must be of UUID size maximum
	MaxServerName = 24
	// NonceLength is the length of the Nonce to be used in the secrets
	NonceLength = 16
	// MaxVersionLen must be maximimum version length
	MaxVersionLen = 4
	// EncryptionEnabledMask mask that identifies the handshake version
	EncryptionEnabledMask = 0x4
)
