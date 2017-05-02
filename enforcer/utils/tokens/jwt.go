package tokens

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/aporeto-inc/trireme/cache"
	"go.uber.org/zap"

	"github.com/dgrijalva/jwt-go"
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
	secrets Secrets
	// cache test
	tokenCache cache.DataStore
}

// NewJWT creates a new JWT token processor
func NewJWT(validity time.Duration, issuer string, secrets Secrets) (*JWTConfig, error) {

	if len(issuer) > MaxServerName {
		return nil, fmt.Errorf("Server ID should be max %d chars. Got %s", MaxServerName, issuer)
	}

	for i := len(issuer); i < MaxServerName; i++ {
		issuer = issuer + " "
	}

	var signMethod jwt.SigningMethod

	if secrets == nil {
		return nil, fmt.Errorf("Secrets can not be nil")
	}

	switch secrets.Type() {
	case PKIType, PKICompactType:
		signMethod = jwt.SigningMethodES256
	case PSKType:
		signMethod = jwt.SigningMethodHS256
	default:
		signMethod = jwt.SigningMethodNone
	}

	return &JWTConfig{
		ValidityPeriod: validity,
		Issuer:         issuer,
		signMethod:     signMethod,
		secrets:        secrets,
		tokenCache:     cache.NewCacheWithExpiration(time.Millisecond * 500),
	}, nil
}

// CreateAndSign  creates a new token, attaches an ephemeral key pair and signs with the issuer
// key. It returns back the token and the private key.
func (c *JWTConfig) CreateAndSign(isAck bool, claims *ConnectionClaims) []byte {

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
		return []byte{}
	}

	// Copy the certificate if needed. Note that we don't send the certificate
	// again for Ack packets to reduce overhead
	if !isAck {
		txKey := c.secrets.TransmittedKey()
		tokenLength := len(strtoken) + len(txKey) + 1 + 2

		token := make([]byte, tokenLength)
		binary.BigEndian.PutUint16(token[0:2], uint16(len(strtoken)))

		copy(token[2:], []byte(strtoken))
		copy(token[2+len(strtoken):], []byte("%"))

		if len(txKey) > 0 {
			copy(token[len(strtoken)+3:], txKey)
		}

		return token
	}

	return []byte(strtoken)

}

// Decode  takes as argument the JWT token and the certificate of the issuer.
// First it verifies the certificate with the local CA pool, and the decodes
// the JWT if the certificate is trusted
func (c *JWTConfig) Decode(isAck bool, data []byte, previousCert interface{}) (*ConnectionClaims, interface{}) {

	var err error
	var ackCert interface{}

	token := data

	jwtClaims := &JWTClaims{}

	// Get the token and data from the buffer and validate the certificate
	// Ack packets don't have a certificate and it must be provided in the
	// Decode function. If certificates are distributed out of band we
	// will look in the certPool for the certificate
	if !isAck {

		tokenLength := int(binary.BigEndian.Uint16(data[0:2]))
		if len(data) <= tokenLength+3 {
			return nil, nil
		}

		token = data[2 : 2+tokenLength]

		certBytes := data[tokenLength+3:]

		if len(token) < len(data) {
			ackCert, err = c.secrets.VerifyPublicKey(certBytes)
			if err != nil {
				return nil, nil
			}
		}
	}

	if cachedClaims, cerr := c.tokenCache.Get(string(token)); cerr == nil {
		return cachedClaims.(*ConnectionClaims), ackCert
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
		return nil, nil
	}

	c.tokenCache.AddOrUpdate(string(token), jwtClaims.ConnectionClaims)

	return jwtClaims.ConnectionClaims, ackCert
}
