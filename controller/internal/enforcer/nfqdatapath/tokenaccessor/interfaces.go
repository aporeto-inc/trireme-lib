package tokenaccessor

import (
	"time"

	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/pkg/tokens"
)

// TokenAccessor define an interface to access LockedTokenEngine
type TokenAccessor interface {
	GetTokenValidity() time.Duration
	GetTokenServerID() string

	CreateAckPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo, secrets secrets.Secrets) ([]byte, error)
	CreateSynPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo, secrets secrets.Secrets) (token []byte, err error)
	CreateSynAckPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo, claimsHeader *claimsheader.ClaimsHeader, secrets secrets.Secrets) (token []byte, err error)
	ParsePacketToken(auth *connection.AuthInfo, data []byte, secrets secrets.Secrets) (*tokens.ConnectionClaims, error)
	ParseAckToken(auth *connection.AuthInfo, data []byte, secrets secrets.Secrets) (*tokens.ConnectionClaims, error)
}
