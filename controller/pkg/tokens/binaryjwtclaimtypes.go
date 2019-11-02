package tokens

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"go.aporeto.io/trireme-lib/v11/policy"
)

// BinaryJWTClaims captures all the custom  clains
type BinaryJWTClaims struct {
	// Tags
	T []string `codec:",omitempty"`
	// Compressed tags
	CT []string `codec:",omitempty"`
	// RMT is the nonce of the remote that has to be signed in the JWT
	RMT []byte `codec:",omitempty"`
	// LCL is the nonce of the local node that has to be signed
	LCL []byte `codec:",omitempty"`
	// EK is the ephemeral EC key for encryption
	EK []byte `codec:",omitempty"`
	// ID is the source PU ID
	ID string `codec:",omitempty"`
	// Expiration time
	ExpiresAt int64 `codec:",omitempty"`
	// SignerKey
	SignerKey []byte `codec:",omitempty"`
}

// ConvertToJWTClaims converts to old claims
func ConvertToJWTClaims(b *BinaryJWTClaims) *JWTClaims {
	return &JWTClaims{
		ConnectionClaims: &ConnectionClaims{
			T:   policy.NewTagStoreFromSlice(b.T),
			CT:  policy.NewTagStoreFromSlice(b.CT),
			RMT: b.RMT,
			LCL: b.LCL,
			EK:  b.EK,
			ID:  b.ID,
		},
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: b.ExpiresAt,
		},
	}
}

// ConvertToBinaryClaims coverts back,
func ConvertToBinaryClaims(j *ConnectionClaims, validity time.Duration) *BinaryJWTClaims {
	b := &BinaryJWTClaims{
		RMT:       j.RMT,
		LCL:       j.LCL,
		EK:        j.EK,
		ID:        j.ID,
		ExpiresAt: time.Now().Add(validity).Unix(),
	}
	if j.T != nil {
		b.T = j.T.Tags
	}
	if j.CT != nil {
		b.CT = j.CT.Tags
	}

	return b
}
