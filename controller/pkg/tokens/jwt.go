package tokens

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
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
	// compressionType determines of compression should be used when creating tokens
	compressionType constants.CompressionType
	// compressionTagLength is the length of tags based on compressionType
	compressionTagLength int
}

// NewJWT creates a new JWT token processor
func NewJWT(validity time.Duration, issuer string, s secrets.Secrets) (*JWTConfig, error) {

	if len(issuer) > MaxServerName {
		return nil, fmt.Errorf("server id should be max %d chars. got %s", MaxServerName, issuer)
	}

	for i := len(issuer); i < MaxServerName; i++ {
		issuer = issuer + " "
	}

	var signMethod jwt.SigningMethod
	compressionType := constants.CompressionTypeNone

	if s == nil {
		return nil, errors.New("secrets can not be nil")
	}

	switch s.Type() {
	case secrets.PKICompactType:
		signMethod = jwt.SigningMethodES256
		compressionType = s.(*secrets.CompactPKI).Compressed
	case secrets.PKIType:
		signMethod = jwt.SigningMethodES256
	case secrets.PSKType:
		signMethod = jwt.SigningMethodHS256
	default:
		signMethod = jwt.SigningMethodNone
	}

	return &JWTConfig{
		ValidityPeriod:       validity,
		Issuer:               issuer,
		signMethod:           signMethod,
		secrets:              s,
		tokenCache:           cache.NewCacheWithExpiration("JWTTokenCache", time.Millisecond*500),
		compressionType:      compressionType,
		compressionTagLength: constants.CompressionTypeToTagLength(compressionType),
	}, nil
}

// CreateAndSign  creates a new token, attaches an ephemeral key pair and signs with the issuer
// key. It also randomizes the source nonce of the token. It returns back the token and the private key.
func (c *JWTConfig) CreateAndSign(isAck bool, claims *ConnectionClaims, nonce []byte) (token []byte, err error) {

	// Combine the application claims with the standard claims
	allclaims := &JWTClaims{
		claims,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(c.ValidityPeriod).Unix(),
			Issuer:    c.Issuer,
		},
	}

	if !isAck {

		zap.L().Debug("claims", zap.Reflect("all", allclaims), zap.String("type", string(c.compressionType)))

		// Handling compression here. If we need to use compression, we will copy
		// the claims to the C claim and remove all the other fields.
		if c.compressionType != constants.CompressionTypeNone {
			tags := allclaims.T
			allclaims.T = nil
			for _, t := range tags.Tags {
				if strings.HasPrefix(t, enforcerconstants.TransmitterLabel) {
					claims.ID = t[len(enforcerconstants.TransmitterLabel)+1:]
				} else {
					claims.C = t
				}
			}

			zap.L().Debug("claims (post)", zap.Reflect("all", allclaims))
		}
	}

	// Create the token and sign with our key
	strtoken, err := jwt.NewWithClaims(c.signMethod, allclaims).SignedString(c.secrets.EncodingKey())
	if err != nil {
		return []byte{}, err
	}

	// Copy the certificate if needed. Note that we don't send the certificate
	// again for Ack packets to reduce overhead
	if !isAck {

		txKey := c.secrets.TransmittedKey()

		totalLength := len(strtoken) + len(txKey) + noncePosition + NonceLength + 1

		token := make([]byte, totalLength)

		// Offset of public key
		binary.BigEndian.PutUint16(token[0:noncePosition], uint16(len(strtoken)))

		// Attach the nonse
		copy(token[noncePosition:], nonce)

		// Copy the JWT tokenn
		copy(token[tokenPosition:], []byte(strtoken))

		token[tokenPosition+len(strtoken)] = '%'
		// Copy the public key
		if len(txKey) > 0 {
			copy(token[tokenPosition+len(strtoken)+1:], txKey)
		}

		return token, nil
	}

	return []byte(strtoken), nil

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
			return nil, nil, nil, errors.New("not enough data")
		}

		tokenLength := int(binary.BigEndian.Uint16(data[0:noncePosition]))
		// Data must be enought to accommodate the token
		if len(data) < tokenPosition+tokenLength+1 {
			return nil, nil, nil, errors.New("invalid token length")
		}

		copy(nonce, data[noncePosition:tokenPosition])

		token = data[tokenPosition : tokenPosition+tokenLength]

		certBytes := data[tokenPosition+tokenLength+1:]
		ackCert, err = c.secrets.VerifyPublicKey(certBytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("invalid public key: %s", err)
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
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to parse token: %s", err)
	}
	if !jwttoken.Valid {
		return nil, nil, nil, errors.New("invalid token")
	}

	if !isAck {

		// Handling of compressed tags in a backward compatible manner. If there are claims
		// arriving in the compressed field then we append them to the tags.
		zap.L().Debug("claims", zap.Reflect("jwt", jwtClaims), zap.String("type", string(c.compressionType)))

		tags := []string{enforcerconstants.TransmitterLabel + "=" + jwtClaims.ConnectionClaims.ID}
		if jwtClaims.ConnectionClaims.T != nil {
			tags = jwtClaims.ConnectionClaims.T.Tags
		}

		// Handle compressed tags
		if c.compressionTagLength != 0 && len(jwtClaims.ConnectionClaims.C) > 0 {

			compressedClaims, err := base64.StdEncoding.DecodeString(jwtClaims.ConnectionClaims.C)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("invalid claims")
			}

			if len(compressedClaims)%c.compressionTagLength != 0 {
				return nil, nil, nil, fmt.Errorf("invalid claims length. compression mismatch %d/%d", len(compressedClaims), c.compressionTagLength)
			}

			for i := 0; i < len(compressedClaims); i = i + c.compressionTagLength {
				tags = append(tags, base64.StdEncoding.EncodeToString(compressedClaims[i:i+c.compressionTagLength]))
			}
		}

		jwtClaims.ConnectionClaims.T = policy.NewTagStoreFromSlice(tags)

		zap.L().Debug("claims (post)", zap.Reflect("jwt", jwtClaims))
	}

	c.tokenCache.AddOrUpdate(string(token), jwtClaims.ConnectionClaims)

	return jwtClaims.ConnectionClaims, nonce, ackCert, nil
}

// Randomize adds a nonce to an existing token. Returns the nonce
func (c *JWTConfig) Randomize(token []byte, nonce []byte) (err error) {

	if len(token) < tokenPosition {
		return errors.New("token is too small")
	}

	copy(token[noncePosition:], nonce)

	return nil
}

// RetrieveNonce returns the nonce of a token. It copies the value
func (c *JWTConfig) RetrieveNonce(token []byte) ([]byte, error) {

	if len(token) < tokenPosition {
		return []byte{}, errors.New("invalid token")
	}

	nonce := make([]byte, NonceLength)
	copy(nonce, token[noncePosition:tokenPosition])

	return nonce, nil
}
