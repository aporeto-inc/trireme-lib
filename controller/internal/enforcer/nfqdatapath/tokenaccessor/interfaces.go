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
	SetToken(serverID string, validity time.Duration, secret secrets.Secrets) error
	GetTokenValidity() time.Duration
	GetTokenServerID() string

	CreateAckPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo) ([]byte, error)
	CreateSynPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo, claimsHeader *claimsheader.ClaimsHeader) (token []byte, err error)
	CreateSynAckPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo, claimsHeader *claimsheader.ClaimsHeader) (token []byte, err error)
	ParsePacketToken(auth *connection.AuthInfo, data []byte) (*tokens.ConnectionClaims, error)
	ParseAckToken(auth *connection.AuthInfo, data []byte) (*tokens.ConnectionClaims, error)
}
