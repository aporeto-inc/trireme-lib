package usertokens

import (
	"context"
	"fmt"
	"net/url"

	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/usertokens/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/usertokens/oidc"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/usertokens/pkitokens"

	"go.uber.org/zap"
)

// Verifier is a generic JWT verifier interface. Different implementations
// will use different client libraries to verify the tokens. Currently
// requires only one method. Given a token, return the claims and whether
// there is a verification error.
type Verifier interface {
	VerifierType() common.JWTType
	Validate(ctx context.Context, token string) ([]string, bool, string, error)
	Callback(ctx context.Context, u *url.URL) (string, string, int, error)
	IssueRedirect(string) string
}

// NewVerifier initializes data structures based on the interface that
// is transmitted over the RPC between main and remote enforcers.
func NewVerifier(ctx context.Context, v Verifier) (Verifier, error) {
	if v == nil {
		return nil, nil
	}
	switch v.VerifierType() {
	case common.PKI:
		p := v.(*pkitokens.PKIJWTVerifier)
		v, err := pkitokens.NewVerifier(p)
		if err != nil {
			return nil, err
		}
		return v, nil
	case common.OIDC:
		p := v.(*oidc.TokenVerifier)
		verifier, err := oidc.NewClient(ctx, p)
		if err != nil {
			zap.L().Debug("usertokens: oidc.NewClient() failed", zap.Error(err))
			return nil, err
		}
		return verifier, nil
	}
	return nil, fmt.Errorf("unknown verifier type")
}
