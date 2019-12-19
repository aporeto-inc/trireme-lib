package common

import (
	"context"
	"time"
)

// ServiceTokenType is the type of the token.
type ServiceTokenType string

// Values of ServiceTokenType
const (
	ServiceTokenTypeOAUTH ServiceTokenType = "oauth"

	ServiceTokenTypeAWS ServiceTokenType = "aws"
)

// ServiceTokenIssuer is an interface of an implementation that can issue service tokens on behalf
// of a PU. The user of the library must provide the implementation. ServiceTokens can be OAUTH
// tokens or cloud provider specific tokens such AWS Role credentials.
type ServiceTokenIssuer interface {
	Issue(ctx context.Context, contextID string, stype ServiceTokenType, audience string, validity time.Duration) (string, error)
}
