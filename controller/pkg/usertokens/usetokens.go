package usertokens

import (
	"context"
	"net/http"

	"go.aporeto.io/trireme-lib/controller/pkg/usertokens/common"
	"go.aporeto.io/trireme-lib/controller/pkg/usertokens/oidc"
	"go.aporeto.io/trireme-lib/controller/pkg/usertokens/pkitokens"
)

// Verifier is a generic JWT verifier interface. Different implementations
// will use different client libraries to verify the tokens. Currently
// requires only one method. Given a token, return the claims and whether
// there is a verification error.
type Verifier interface {
	VerifierType() common.JWTType
	Validate(ctx context.Context, token string, r *http.Request) ([]string, bool, string, error)
	Callback(r *http.Request) (string, string, int, error)
	IssueRedirect(string) string
}

// NewVerifier initializes data structures based on the interface that
// is transmitted over the RPC between main and remote enforcers.
func NewVerifier(v Verifier) Verifier {
	if v == nil {
		return nil
	}
	switch v.VerifierType() {
	case common.PKI:
		p := v.(*pkitokens.PKIJWTVerifier)
		v, err := pkitokens.NewVerifier(p)
		if err != nil {
			return nil
		}
		return v
	case common.OIDC:
		p := v.(*oidc.TokenVerifier)
		verifier, err := oidc.NewClient(context.Background(), p)
		// TODO figure out error handling
		if err != nil {
			return nil
		}
		return verifier
	}
	return nil
}
