package tokens

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

// BinaryJWTClaims captures all the custom  claims
type BinaryJWTClaims struct {
	// Tags
	T []string `codec:",omitempty"`
	// Compressed tags
	CT []string `codec:",omitempty"`
	// RMT is the nonce of the remote that has to be signed in the JWT
	RMT []byte `codec:",omitempty"`
	// LCL is the nonce of the local node that has to be signed
	LCL []byte `codec:",omitempty"`
	// DEK is the datapath ephemeral keys used to derived shared keys during the handshake
	DEK []byte `codec:",omitempty"`
	// SDEK is the signature of the ephemeral key
	SDEK []byte `codec:",omitempty"`
	// ID is the source PU ID
	ID string `codec:",omitempty"`
	// Expiration time
	ExpiresAt int64 `codec:",omitempty"`
	// SignerKey
	SignerKey []byte `codec:",omitempty"`
	// P holds the ping payload
	P *policy.PingPayload `codec:",omitempty"`
	// DEKV2 is the datapath ephemeral key V2 used to derived shared keys during the handshake
	DEKV2 []byte `codec:",omitempty"`
	// SDEK is the signature of the ephemeral key V2
	SDEKV2 []byte `codec:",omitempty"`
}

// JWTClaims captures all the custom  clains
type JWTClaims struct {
	*ConnectionClaims
	jwt.StandardClaims
}

//CopyToConnectionClaims copies the binary jwt claims to connection claims
func CopyToConnectionClaims(b *BinaryJWTClaims, connClaims *ConnectionClaims) {
	*connClaims = ConnectionClaims{
		T:      policy.NewTagStoreFromSlice(b.T),
		CT:     policy.NewTagStoreFromSlice(b.CT),
		RMT:    b.RMT,
		LCL:    b.LCL,
		SDEKV1: b.SDEK,
		DEKV1:  b.DEK,
		SDEKV2: b.SDEKV2,
		DEKV2:  b.DEKV2,
		ID:     b.ID,
		P:      b.P,
	}
}

// ConvertToJWTClaims converts to old claims
func ConvertToJWTClaims(b *BinaryJWTClaims) *JWTClaims {
	return &JWTClaims{
		ConnectionClaims: &ConnectionClaims{
			T:      policy.NewTagStoreFromSlice(b.T),
			CT:     policy.NewTagStoreFromSlice(b.CT),
			RMT:    b.RMT,
			LCL:    b.LCL,
			SDEKV1: b.SDEK,
			DEKV1:  b.DEK,
			SDEKV2: b.SDEKV2,
			DEKV2:  b.DEKV2,
			ID:     b.ID,
			P:      b.P,
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
		SDEK:      j.SDEKV1,
		DEK:       j.DEKV1,
		SDEKV2:    j.SDEKV2,
		DEKV2:     j.DEKV2,
		ID:        j.ID,
		ExpiresAt: time.Now().Add(validity).Unix(),
		P:         j.P,
	}
	if j.T != nil {
		b.T = j.T.GetSlice()
	}
	if j.CT != nil {
		b.CT = j.CT.GetSlice()
	}

	return b
}
