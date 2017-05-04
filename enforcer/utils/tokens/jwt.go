package tokens

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/crypto"
	"github.com/aporeto-inc/trireme/enforcer/utils/secrets"
	"go.uber.org/zap"

	"github.com/dgrijalva/jwt-go"
)

var (
	noncePosition = 2
	tokenPosition = 2 + NonceLength
)

// JWTClaims captures all the custom  clains
type JWTClaims struct {
	*ConnectionClaims
	jwt.StandardClaims
}

// JWTConfig configures the JWT token generator with the standard parameters. One
// configuration is assigned to each server
type JWTConfig struct {
	// ValidityPeriod  period of the JWT
	ValidityPeriod time.Duration
	// Issuer is the server that issues the JWT
	Issuer string
	// signMethod is the method used to sign the JWT
	signMethod jwt.SigningMethod
	// secrets is the secrets used for signing and verifying the JWT
	secrets secrets.Secrets
	// cache test
	tokenCache cache.DataStore
}

// NewJWT creates a new JWT token processor
func NewJWT(validity time.Duration, issuer string, s secrets.Secrets) (*JWTConfig, error) {

	if len(issuer) > MaxServerName {
		return nil, fmt.Errorf("Server ID should be max %d chars. Got %s", MaxServerName, issuer)
	}

	for i := len(issuer); i < MaxServerName; i++ {
		issuer = issuer + " "
	}

	var signMethod jwt.SigningMethod

	if s == nil {
		return nil, fmt.Errorf("Secrets can not be nil")
	}

	switch s.Type() {
	case secrets.PKIType, secrets.PKICompactType:
		signMethod = jwt.SigningMethodES256
	case secrets.PSKType:
		signMethod = jwt.SigningMethodHS256
	default:
		signMethod = jwt.SigningMethodNone
	}

	return &JWTConfig{
		ValidityPeriod: validity,
		Issuer:         issuer,
		signMethod:     signMethod,
		secrets:        s,
		tokenCache:     cache.NewCacheWithExpiration(time.Millisecond * 500),
	}, nil
}

// CreateAndSign  creates a new token, attaches an ephemeral key pair and signs with the issuer
// key. It also randomizes the source nonce of the token. It returns back the token and the private key.
func (c *JWTConfig) CreateAndSign(isAck bool, claims *ConnectionClaims) (token []byte, nonce []byte, err error) {

	// Combine the application claims with the standard claims
	allclaims := &JWTClaims{
		claims,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(c.ValidityPeriod).Unix(),
			Issuer:    c.Issuer,
		},
	}

	// Create the token and sign with our key
	strtoken, err := jwt.NewWithClaims(c.signMethod, allclaims).SignedString(c.secrets.EncodingKey())
	if err != nil {
		return []byte{}, []byte{}, err
	}

	// Copy the certificate if needed. Note that we don't send the certificate
	// again for Ack packets to reduce overhead
	if !isAck {

		nonce, err := crypto.GenerateRandomBytes(NonceLength)
		if err != nil {
			return []byte{}, []byte{}, err
		}

		txKey := c.secrets.TransmittedKey()

		totalLength := len(strtoken) + len(txKey) + noncePosition + NonceLength + 1

		token := make([]byte, totalLength)

		// Offset of public key
		binary.BigEndian.PutUint16(token[0:noncePosition], uint16(len(strtoken)))

		// Attach the nonse
		copy(token[noncePosition:], nonce)

		// Copy the JWT tokenn
		copy(token[tokenPosition:], []byte(strtoken))

		token[tokenPosition+len(strtoken)] = []byte("%")[0]
		// Copy the public key
		if len(txKey) > 0 {
			copy(token[tokenPosition+len(strtoken)+1:], txKey)
		}

		return token, nonce, nil
	}

	return []byte(strtoken), []byte{}, nil

}

// Decode  takes as argument the JWT token and the certificate of the issuer.
// First it verifies the certificate with the local CA pool, and the decodes
// the JWT if the certificate is trusted
func (c *JWTConfig) Decode(isAck bool, data []byte, previousCert interface{}) (claims *ConnectionClaims, nonce []byte, publicKey interface{}, err error) {

	var ackCert interface{}

	token := data

	jwtClaims := &JWTClaims{}

	nonce = make([]byte, NonceLength)

	// Get the token and data from the buffer and validate the certificate
	// Ack packets don't have a certificate and it must be provided in the
	// Decode function. If certificates are distributed out of band we
	// will look in the certPool for the certificate
	if !isAck {

		// We must have at least enough data to get the length
		if len(data) < tokenPosition {
			return nil, nil, nil, fmt.Errorf("bad token length")
		}

		tokenLength := int(binary.BigEndian.Uint16(data[0:noncePosition]))
		// Data must be enought to accommodate the token
		if len(data) < tokenPosition+tokenLength+1 {
			return nil, nil, nil, fmt.Errorf("bad token length")
		}

		copy(nonce, data[noncePosition:tokenPosition])

		token = data[tokenPosition : tokenPosition+tokenLength]

		certBytes := data[tokenPosition+tokenLength+1:]

		ackCert, err = c.secrets.VerifyPublicKey(certBytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("bad public key")
		}

		if cachedClaims, cerr := c.tokenCache.Get(string(token)); cerr == nil {
			return cachedClaims.(*ConnectionClaims), nonce, ackCert, nil
		}
	}

	// Parse the JWT token with the public key recovered
	jwttoken, err := jwt.ParseWithClaims(string(token), jwtClaims, func(token *jwt.Token) (interface{}, error) {
		server := token.Claims.(*JWTClaims).Issuer
		server = strings.Trim(server, " ")
		return c.secrets.DecodingKey(server, ackCert, previousCert)
	})

	// If error is returned or the token is not valid, reject it
	if err != nil || !jwttoken.Valid {
		zap.L().Error("ParseWithClaim failed", zap.Error(err))
		return nil, nil, nil, fmt.Errorf("Invalid token")
	}

	c.tokenCache.AddOrUpdate(string(token), jwtClaims.ConnectionClaims)

	return jwtClaims.ConnectionClaims, nonce, ackCert, nil
}

// Randomize adds a nonce to an existing token. Returns the nonce
func (c *JWTConfig) Randomize(token []byte) (nonce []byte, err error) {

	if len(token) < tokenPosition {
		return []byte{}, fmt.Errorf("Token is too small")
	}

	nonce, err = crypto.GenerateRandomBytes(NonceLength)
	if err != nil {
		return []byte{}, err
	}

	copy(token[noncePosition:], nonce)

	return nonce, nil
}

// RetrieveNonce returns the nonce of a token. It copies the value
func (c *JWTConfig) RetrieveNonce(token []byte) ([]byte, error) {
	if len(token) < tokenPosition {
		return []byte{}, fmt.Errorf("Invalid token")
	}

	nonce := make([]byte, NonceLength)
	copy(nonce, token[noncePosition:tokenPosition])
	return nonce, nil
}
