package pkiverifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"github.com/dgrijalva/jwt-go"
	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/cache"
)

const (
	// defaultValidity is the default cache validity in seconds
	defaultValidity = 1
)

// VerifierClaims captures all the clains of the verifier that is basically the public key
type VerifierClaims struct {
	X *big.Int
	Y *big.Int
	jwt.StandardClaims
}

// PKIConfiguration is the configuration of the verifier
type PKIConfiguration struct {
	publicKey  *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey
	signMethod jwt.SigningMethod
	keycache   cache.DataStore
	validity   time.Duration
}

// NewConfig initializes a new signer structure
func NewConfig(publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey, cacheValiditiy time.Duration) *PKIConfiguration {

	validity := defaultValidity * time.Second
	if cacheValiditiy > 0 {
		validity = cacheValiditiy
	}

	return &PKIConfiguration{
		publicKey:  publicKey,
		privateKey: privateKey,
		signMethod: jwt.SigningMethodES256,
		keycache:   cache.NewCacheWithExpiration(validity),
		validity:   validity,
	}
}

// Verify verifies a token and returns the public key
func (p *PKIConfiguration) Verify(token []byte) (*ecdsa.PublicKey, error) {

	tokenString := string(token)

	claims := &VerifierClaims{}

	if pk, err := p.keycache.Get(tokenString); err == nil {
		return pk.(*ecdsa.PublicKey), nil
	}

	// Parse the JWT token with the public key recovered
	jwttoken, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return p.publicKey, nil
	})

	if err != nil || !jwttoken.Valid {
		zap.L().Error("Failed to parse public key structure", zap.Error(err))
		return nil, fmt.Errorf("error in token %v ", err.Error())
	}

	pk := KeyFromClaims(claims)

	if time.Now().Add(p.validity).Unix() <= claims.ExpiresAt {
		p.keycache.AddOrUpdate(tokenString, pk)
	}

	return pk, nil
}

// CreateTokenFromCertificate creates and signs a token
func (p *PKIConfiguration) CreateTokenFromCertificate(cert *x509.Certificate) ([]byte, error) {

	// Combine the application claims with the standard claims
	claims := &VerifierClaims{
		X: cert.PublicKey.(*ecdsa.PublicKey).X,
		Y: cert.PublicKey.(*ecdsa.PublicKey).Y,
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
func KeyFromClaims(claims *VerifierClaims) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     claims.X,
		Y:     claims.Y,
	}
}
