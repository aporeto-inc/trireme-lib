package tokenprocessor

import (
	"github.com/aporeto-inc/trireme-lib/enforcer/connection"
	"github.com/aporeto-inc/trireme-lib/enforcer/pucontext"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/tokens"
)

// TokenProcessor is an interface to process tokens
type TokenProcessor interface {
	CreateAckPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo) ([]byte, error)
	CreateSynPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo) (token []byte, err error)
	CreateSynAckPacketToken(context *pucontext.PUContext, auth *connection.AuthInfo) (token []byte, err error)
	ParsePacketToken(auth *connection.AuthInfo, data []byte) (*tokens.ConnectionClaims, error)
	ParseAckToken(auth *connection.AuthInfo, data []byte) (*tokens.ConnectionClaims, error)
}
