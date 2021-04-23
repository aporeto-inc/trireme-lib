package tokenaccessor

import (
	"crypto/ecdsa"
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/ephemeralkeys"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pkiverifier"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/tokens"
)

// TokenAccessor define an interface to access LockedTokenEngine
type TokenAccessor interface {
	GetTokenValidity() time.Duration
	GetTokenServerID() string

	// Token creation methods.
	CreateAckPacketToken(proto314 bool, secretKey []byte, claims *tokens.ConnectionClaims, encodedBuf []byte) ([]byte, error)
	CreateSynPacketToken(claims *tokens.ConnectionClaims, encodedBuf []byte, nonce []byte, claimsHeader *claimsheader.ClaimsHeader, secrets secrets.Secrets) ([]byte, error)

	CreateSynAckPacketToken(proto314 bool, claims *tokens.ConnectionClaims, encodedBuf []byte, nonce []byte, claimsHeader *claimsheader.ClaimsHeader, secrets secrets.Secrets, secretKey []byte) ([]byte, error)
	// Token parsing methods.
	ParsePacketToken(privateKey *ephemeralkeys.PrivateKey, data []byte, secrets secrets.Secrets, c *tokens.ConnectionClaims, b bool) ([]byte, *claimsheader.ClaimsHeader, *pkiverifier.PKIControllerInfo, []byte, string, bool, error)
	ParseAckToken(proto314 bool, secretKey []byte, nonce []byte, data []byte, connClaims *tokens.ConnectionClaims) error

	Randomize([]byte, []byte) error
	Sign([]byte, *ecdsa.PrivateKey) ([]byte, error)
}
