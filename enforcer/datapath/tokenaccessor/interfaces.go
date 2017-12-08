package tokenaccessor

import (
	"time"

	"github.com/aporeto-inc/trireme-lib/enforcer/connection"
	"github.com/aporeto-inc/trireme-lib/enforcer/pucontext"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/tokens"
)

// TokenAccessor define an interface to access LockedTokenEngine
type TokenAccessor interface {
	SetToken(serverID string, validity time.Duration, secret secrets.Secrets) error
	GetTokenValidity() time.Duration
	GetTokenServerID() string

	CreateAckPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo) ([]byte, error)
	CreateSynPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo) (token []byte, err error)
	CreateSynAckPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo) (token []byte, err error)
	ParsePacketToken(auth *connection.AuthInfo, data []byte) (*tokens.ConnectionClaims, error)
	ParseAckToken(auth *connection.AuthInfo, data []byte) (*tokens.ConnectionClaims, error)
}
