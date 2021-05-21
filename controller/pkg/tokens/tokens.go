package tokens

import (
	"crypto/ecdsa"

	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/ephemeralkeys"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pkiverifier"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

// ConnectionClaims captures all the claim information
type ConnectionClaims struct {
	T *policy.TagStore `json:",omitempty"`
	// RMT is the nonce of the remote that has to be signed in the JWT
	RMT []byte `json:",omitempty"`
	// LCL is the nonce of the local node that has to be signed
	LCL []byte `json:",omitempty"`
	// DEKV1 is the datapath ephemeral keys used to derived shared keys during the handshake
	DEKV1 []byte `json:",omitempty"`
	// SDEKV1 is the signature of the ephemeral key
	SDEKV1 []byte `json:",omitempty"`
	// C is the compressed tags in one string
	CT *policy.TagStore `json:",omitempty"`
	// ID is the source PU ID
	ID string `json:",omitempty"`
	// RemoteID is the ID of the remote if known.
	RemoteID string `json:",omitempty"`
	// H is the claims header
	H claimsheader.HeaderBytes `json:",omitempty"`
	// P holds the ping payload
	P *policy.PingPayload `codec:",omitempty"`
	// DEKV2 is the datapath ephemeral keys used to derived shared keys during the handshake
	DEKV2 []byte `json:",omitempty"`
	// SDEKV2 is the signature of the ephemeral key
	SDEKV2 []byte `json:",omitempty"`
}

// TokenEngine is the interface to the different implementations of tokens
type TokenEngine interface {
	// CreteAndSign creates a token, signs it and produces the final byte string
	CreateSynToken(claims *ConnectionClaims, encodedBuf []byte, nonce []byte, header *claimsheader.ClaimsHeader, secrets secrets.Secrets) ([]byte, error)
	CreateSynAckToken(proto314 bool, claims *ConnectionClaims, encodedBuf []byte, nonce []byte, header *claimsheader.ClaimsHeader, secrets secrets.Secrets, secretKey []byte) ([]byte, error)
	CreateAckToken(proto314 bool, secretKey []byte, claims *ConnectionClaims, encodedBuf []byte, header *claimsheader.ClaimsHeader) ([]byte, error)

	DecodeSyn(isSynAck bool, data []byte, privateKey *ephemeralkeys.PrivateKey, secrets secrets.Secrets, connClaims *ConnectionClaims) ([]byte, *claimsheader.ClaimsHeader, []byte, *pkiverifier.PKIControllerInfo, bool, error)
	DecodeAck(proto314 bool, secretKey []byte, data []byte, connClaims *ConnectionClaims) error

	// Randomize inserts a source nonce in an existing token - New nonce will be
	// create every time the token is transmitted as a challenge to the other side
	// even when the token is cached. There should be space in the token already.
	// Returns an error if there is no space
	Randomize([]byte, []byte) (err error)
	Sign([]byte, *ecdsa.PrivateKey) ([]byte, error)
}

const (
	// MaxServerName must be of UUID size maximum
	MaxServerName = 24
	// NonceLength is the length of the Nonce to be used in the secrets
	NonceLength = 16
)
