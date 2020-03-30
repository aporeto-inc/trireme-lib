package pkitokens

import (
	"context"
	"crypto"
	"fmt"
	"io/ioutil"
	"net/url"

	jwt "github.com/dgrijalva/jwt-go"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/usertokens/common"
)

// PKIJWTVerifier is a generic JWT PKI verifier. It assumes that the tokens have
// been signed by a private key, and it validates them with the provide public key.
// This is a simple and stateless verifier that doesn't depend on central server
// for validating the tokens. The public key is provided out-of-band.
type PKIJWTVerifier struct {
	JWTCertPEM  []byte
	keys        []crypto.PublicKey
	RedirectURL string
}

// NewVerifierFromFile assumes that the input is provided as file path.
func NewVerifierFromFile(jwtcertPath string, redirectURI string, redirectOnFail, redirectOnNoToken bool) (*PKIJWTVerifier, error) {
	jwtCertPEM, err := ioutil.ReadFile(jwtcertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWT signing certificates or public keys from file: %s", err)
	}
	return NewVerifierFromPEM(jwtCertPEM, redirectURI, redirectOnFail, redirectOnNoToken)
}

// NewVerifierFromPEM assumes that the input is a PEM byte array.
func NewVerifierFromPEM(jwtCertPEM []byte, redirectURI string, redirectOnFail, redirectOnNoToken bool) (*PKIJWTVerifier, error) {
	keys, err := parsePublicKeysFromPEM(jwtCertPEM)
	// pay attention to the return format of parsePublicKeysFromPEM
	// when checking for an error here
	if keys == nil && err != nil {
		return nil, fmt.Errorf("failed to read JWT signing certificates or public keys from PEM: %s", err)
	}
	return &PKIJWTVerifier{
		JWTCertPEM:  jwtCertPEM,
		keys:        keys,
		RedirectURL: redirectURI,
	}, nil
}

// NewVerifier creates a new verifier from the provided configuration.
func NewVerifier(v *PKIJWTVerifier) (*PKIJWTVerifier, error) {
	if len(v.JWTCertPEM) == 0 {
		return v, nil
	}
	keys, err := parsePublicKeysFromPEM(v.JWTCertPEM)
	// pay attention to the return format of parsePublicKeysFromPEM
	// when checking for an error here
	if keys == nil && err != nil {
		return nil, fmt.Errorf("failed to parse JWT signing certificates or public keys from PEM: %s", err)
	}
	v.keys = keys
	return v, nil
}

// Validate parses a generic JWT token and flattens the claims in a normalized form. It
// assumes that any of the JWT signing certs or public keys will validate the token.
func (j *PKIJWTVerifier) Validate(ctx context.Context, tokenString string) ([]string, bool, string, error) {
	if len(tokenString) == 0 {
		return []string{}, false, tokenString, fmt.Errorf("Empty token")
	}
	if len(j.keys) == 0 {
		return []string{}, false, tokenString, fmt.Errorf("No public keys loaded into verifier")
	}

	// iterate over all public keys that we have and try to validate the token
	// the first one to succeed will be used
	var errs []error
	for _, key := range j.keys {
		claims := &jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			switch token.Method.(type) {
			case *jwt.SigningMethodECDSA:
				if isECDSAPublicKey(key) {
					return key, nil
				}
			case *jwt.SigningMethodRSA:
				if isRSAPublicKey(key) {
					return key, nil
				}
			default:
				return nil, fmt.Errorf("unsupported signing method '%T'", token.Method)
			}
			return nil, fmt.Errorf("signing method '%T' and public key type '%T' mismatch", token.Method, key)
		})

		// cover all error cases after parsing/verifying
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if token == nil {
			errs = append(errs, fmt.Errorf("no token was parsed"))
			continue
		}
		if !token.Valid {
			errs = append(errs, fmt.Errorf("token failed to verify against public key"))
			continue
		}

		// return successful on match/verification with the first key
		attributes := []string{}
		for k, v := range *claims {
			attributes = append(attributes, common.FlattenClaim(k, v)...)
		}
		return attributes, false, tokenString, nil
	}

	// generate a detailed error
	var detailedError string
	for i, err := range errs {
		detailedError += err.Error()
		if i+1 < len(errs) {
			detailedError += "; "
		}
	}
	return []string{}, false, tokenString, fmt.Errorf("Invalid token - errors: [%s]", detailedError)
}

// VerifierType returns the type of the verifier.
func (j *PKIJWTVerifier) VerifierType() common.JWTType {
	return common.PKI
}

// Callback is called by an IDP. Not implemented here. No central authorizer for the tokens.
func (j *PKIJWTVerifier) Callback(ctx context.Context, u *url.URL) (string, string, int, error) {
	return "", "", 0, nil
}

// IssueRedirect issues a redirect. Not implemented. There is no need for a redirect.
func (j *PKIJWTVerifier) IssueRedirect(originURL string) string {
	return ""
}
