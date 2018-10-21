package pkitokens

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"go.aporeto.io/tg/tglib"
	"go.aporeto.io/trireme-lib/controller/pkg/usertokens/common"
)

// PKIJWTVerifier is a generic JWT PKI verifier. It assumes that the tokens have
// been signed by a private key, and it validates them with the provide public key.
// This is a simple and stateless verifier that doesn't depend on central server
// for validating the tokens. The public key is provided out-of-band.
type PKIJWTVerifier struct {
	JWTCertPEM  []byte
	jwtCert     *x509.Certificate
	RedirectURL string
}

// NewVerifierFromFile assumes that the input is provided as file path.
func NewVerifierFromFile(jwtcertPath string, redirectURI string, redirectOnFail, redirectOnNoToken bool) (*PKIJWTVerifier, error) {
	jwtCertPEM, err := ioutil.ReadFile(jwtcertPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read jwt signing certificate from file: %s", err)
	}
	return NewVerifierFromPEM(jwtCertPEM, redirectURI, redirectOnFail, redirectOnNoToken)
}

// NewVerifierFromPEM assumes that the input is a PEM byte array.
func NewVerifierFromPEM(jwtCertPEM []byte, redirectURI string, redirectOnFail, redirectOnNoToken bool) (*PKIJWTVerifier, error) {
	jwtCertificate, err := tglib.ParseCertificate(jwtCertPEM)
	if err != nil {
		return nil, fmt.Errorf("Failed to read jwt signing certificate from PEM: %s", err)
	}
	return &PKIJWTVerifier{
		JWTCertPEM:  jwtCertPEM,
		jwtCert:     jwtCertificate,
		RedirectURL: redirectURI,
	}, nil
}

// NewVerifier creates a new verifier from the provided configuration.
func NewVerifier(v *PKIJWTVerifier) (*PKIJWTVerifier, error) {
	if len(v.JWTCertPEM) == 0 {
		return v, nil
	}
	jwtCertificate, err := tglib.ParseCertificate(v.JWTCertPEM)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse certificate: %s", err)
	}
	v.jwtCert = jwtCertificate
	return v, nil
}

// Validate parses a generic JWT token and flattens the claims in a normalized form. It
// assumes that the JWT signing certificate will validate the token.
func (j *PKIJWTVerifier) Validate(ctx context.Context, tokenString string) ([]string, bool, error) {
	if len(tokenString) == 0 {
		return []string{}, false, fmt.Errorf("Empty token")
	}
	claims := &jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if j.jwtCert == nil {
			return nil, fmt.Errorf("Nil certificate - ignore")
		}
		switch token.Method {
		case token.Method.(*jwt.SigningMethodECDSA):
			if rcert, ok := j.jwtCert.PublicKey.(*ecdsa.PublicKey); ok {
				return rcert, nil
			}
		case token.Method.(*jwt.SigningMethodRSA):
			if rcert, ok := j.jwtCert.PublicKey.(*rsa.PublicKey); ok {
				return rcert, nil
			}
		default:
			return nil, fmt.Errorf("Unknown signing method")
		}
		return nil, fmt.Errorf("Signing method does not match certificate")
	})
	if err != nil || token == nil || !token.Valid {
		return []string{}, false, fmt.Errorf("Invalid token")
	}

	attributes := []string{}
	for k, v := range *claims {
		attributes = append(attributes, common.FlattenClaim(k, v)...)
	}
	return attributes, false, nil
}

// VerifierType returns the type of the verifier.
func (j *PKIJWTVerifier) VerifierType() common.JWTType {
	return common.PKI
}

// Callback is called by an IDP. Not implemented here. No central authorizer for the tokens.
func (j *PKIJWTVerifier) Callback(r *http.Request) (string, string, int, error) {
	return "", "", 0, nil
}

// IssueRedirect issues a redirect. Not implemented. There is no need for a redirect.
func (j *PKIJWTVerifier) IssueRedirect(originURL string) string {
	return ""
}
