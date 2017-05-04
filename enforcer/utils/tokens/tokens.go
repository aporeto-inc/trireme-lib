package tokens

import "github.com/aporeto-inc/trireme/policy"

// ConnectionClaims captures all the claim information
type ConnectionClaims struct {
	T *policy.TagsMap
	// RMT is the nonce of the remote that has to be signed in the JWT
	RMT []byte
	// LCL is the nonce of the local node that has to be signed
	LCL []byte
	// EK is the ephemeral EC key for encryption
	EK []byte
}

// TokenEngine is the interface to the different implementations of tokens
type TokenEngine interface {
	// CreteAndSign creates a token, signs it and produces the final byte string
	CreateAndSign(isAck bool, claims *ConnectionClaims) (token []byte, nonce []byte, err error)
	// Decode decodes an incoming buffer and returns the claims and the sender certificate
	Decode(isAck bool, data []byte, previousCert interface{}) (claims *ConnectionClaims, nonce []byte, publicKey interface{}, err error)
	// Randomize inserts a source nonce in an existing token - New nonce will be
	// create every time the token is transmitted as a challenge to the other side
	// even when the token is cached. There should be space in the token already.
	// Returns an error if there is no space
	Randomize([]byte) (nonce []byte, err error)
	// RetrieveNonce retrieves the nonce from the token only. Returns the nonce
	// or an error if the nonce cannot be decoded
	RetrieveNonce([]byte) ([]byte, error)
}

const (
	// MaxServerName must be of UUID size maximum
	MaxServerName = 36
	// NonceLength is the length of the Nonce to be used in the secrets
	NonceLength = 16
)
