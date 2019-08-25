package pkiverifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"math/big"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"go.aporeto.io/trireme-lib/utils/cache"
)

const (
	// defaultValidity is the default cache validity in seconds
	defaultValidity = 1
)

// PKITokenIssuer is the interface of an object that can issue a PKI token.
type PKITokenIssuer interface {
	CreateTokenFromCertificate(*x509.Certificate, []string) ([]byte, error)
}

// PKITokenVerifier is the interface of an object that can verify a PKI token.
type PKITokenVerifier interface {
	Verify([]byte) (*DatapathKey, error)
}

type verifierClaims struct {
	X    *big.Int
	Y    *big.Int
	Tags []string `json:"tags,omitempty"`
	jwt.StandardClaims
}

type tokenManager struct {
	publicKeys []*ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey
	signMethod jwt.SigningMethod
	keycache   cache.DataStore
	validity   time.Duration
}

// DatapathKey holds the data path key with the corresponding claims.
type DatapathKey struct {
	PublicKey *ecdsa.PublicKey
	Tags      []string
}

// NewPKIIssuer initializes a new signer structure
func NewPKIIssuer(privateKey *ecdsa.PrivateKey) PKITokenIssuer {

	return &tokenManager{
		privateKey: privateKey,
		signMethod: jwt.SigningMethodES256,
	}
}

// NewPKIVerifier returns a new PKIConfiguration.
func NewPKIVerifier(publicKeys []*ecdsa.PublicKey, cacheValidity time.Duration) PKITokenVerifier {

	validity := defaultValidity * time.Second
	if cacheValidity > 0 {
		validity = cacheValidity
	}

	return &tokenManager{
		publicKeys: publicKeys,
		signMethod: jwt.SigningMethodES256,
		keycache:   cache.NewCacheWithExpiration("PKIVerifierKey", validity),
		validity:   validity,
	}
}

// Verify verifies a token and returns the public key
func (p *tokenManager) Verify(token []byte) (*DatapathKey, error) {

	tokenString := string(token)
	if pk, err := p.keycache.Get(tokenString); err == nil {
		return pk.(*DatapathKey), err
	}

	claims := &verifierClaims{}
	var t *jwt.Token
	var err error
	for _, pk := range p.publicKeys {

		if pk == nil {
			continue
		}

		t, err = jwt.ParseWithClaims(tokenString, claims, func(_ *jwt.Token) (interface{}, error) { // nolint
			return pk, nil
		})
		if err != nil || !t.Valid {
			continue
		}

		dp := &DatapathKey{
			PublicKey: KeyFromClaims(claims),
			Tags:      claims.Tags,
		}

		if time.Now().Add(p.validity).Unix() <= claims.ExpiresAt {
			p.keycache.AddOrUpdate(tokenString, dp)
		}
		return dp, nil
	}

	return nil, errors.New("unable to verify token against any available public key")
}

// CreateTokenFromCertificate creates and signs a token
func (p *tokenManager) CreateTokenFromCertificate(cert *x509.Certificate, tags []string) ([]byte, error) {

	// Combine the application claims with the standard claims
	claims := &verifierClaims{
		X:    cert.PublicKey.(*ecdsa.PublicKey).X,
		Y:    cert.PublicKey.(*ecdsa.PublicKey).Y,
		Tags: tags,
	}
	claims.ExpiresAt = cert.NotAfter.Unix()

	// Create the token and sign with our key
	strtoken, err := jwt.NewWithClaims(p.signMethod, claims).SignedString(p.privateKey)
	if err != nil {
		return []byte{}, err
	}

	return []byte(strtoken), nil
}

// KeyFromClaims creates the public key structure from the claims
func KeyFromClaims(claims *verifierClaims) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     claims.X,
		Y:     claims.Y,
	}
}
