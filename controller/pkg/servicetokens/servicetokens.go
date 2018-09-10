package servicetokens

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/bluele/gcache"
	"github.com/dgrijalva/jwt-go"
	"go.uber.org/zap"

	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/utils/cache"
)

var (
	localCache = cache.NewCacheWithExpiration("tokens", time.Second*10)
)

// JWTClaims is the structure of the claims we are sending on the wire.
type JWTClaims struct {
	jwt.StandardClaims
	SourceID string
	Scopes   []string
	Profile  []string
}

// Verifier keeps all the structures for processing tokens.
type Verifier struct {
	secrets    secrets.Secrets
	globalCert *x509.Certificate
	tokenCache gcache.Cache
	sync.RWMutex
}

// NewVerifier creates a new Aporeto JWT Verifier. The globalCertificate is optional
// and is needed for configurations that do not transmit the token over the wire.
func NewVerifier(s secrets.Secrets, globalCertificate *x509.Certificate) *Verifier {
	return &Verifier{
		secrets:    s,
		globalCert: globalCertificate,
		// tokenCache will cache the token results to accelerate performance
		tokenCache: gcache.New(2048).LRU().Expiration(20 * time.Second).Build(),
	}
}

// ParseToken parses and validates the JWT token, give the publicKey. It returns the scopes
// the identity and the sourceID of the provided token. These tokens are strictly
// signed with EC.
// TODO: We can be more flexible with the algorithm selection here.
func (p *Verifier) ParseToken(token string, publicKey string) (string, []string, []string, error) {
	p.RLock()
	defer p.RUnlock()

	if data, _ := p.tokenCache.Get(token); data != nil {
		claims := data.(*JWTClaims)
		return claims.SourceID, claims.Scopes, claims.Profile, nil
	}

	// if a public key is transmitted in the wire, we need to verify its validity and use it.
	// Otherwise we use the public key of the stored secrets.
	var key *ecdsa.PublicKey
	var ok bool
	if len(publicKey) > 0 {
		// Public keys are cached and verified and they are the compact keys
		// that we transmit in all other requests signed by the CA. These keys
		// are not full certificates.
		gKey, err := p.secrets.VerifyPublicKey([]byte(publicKey))
		if err != nil {
			return "", nil, nil, fmt.Errorf("Cannot validate public key: %s", err)
		}
		key, ok = gKey.(*ecdsa.PublicKey)
		if !ok {
			return "", nil, nil, fmt.Errorf("Provided public key not supported")
		}
	} else {
		if p.globalCert == nil {
			return "", nil, nil, fmt.Errorf("Cannot validate global public key")
		}
		key, ok = p.globalCert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return "", nil, nil, fmt.Errorf("Global public key is not supported")
		}
	}

	claims := &JWTClaims{}
	if _, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	}); err != nil {
		return "", nil, nil, err
	}
	if err := p.tokenCache.Set(token, claims); err != nil {
		zap.L().Error("Failed to cache token", zap.Error(err))
	}
	return claims.SourceID, claims.Scopes, claims.Profile, nil
}

// UpdateSecrets updates the secrets of the token Verifier.
func (p *Verifier) UpdateSecrets(s secrets.Secrets, globalCert *x509.Certificate) {
	p.Lock()
	defer p.Unlock()

	p.secrets = s
	p.globalCert = globalCert
}

// CreateAndSign creates a new JWT token based on the Aporeto identities.
func CreateAndSign(server string, profile, scopes []string, id string, validity time.Duration, gkey interface{}) (string, error) {
	key, ok := gkey.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("Not a valid private key format")
	}
	if token, err := localCache.Get(id); err == nil {
		return token.(string), nil
	}
	claims := &JWTClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    server,
			ExpiresAt: time.Now().Add(validity).Unix(),
		},
		Profile:  profile,
		Scopes:   scopes,
		SourceID: id,
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(key)
	if err != nil {
		return "", err
	}

	localCache.AddOrUpdate(id, token)
	return token, nil
}
