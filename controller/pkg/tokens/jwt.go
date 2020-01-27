package tokens

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	enforcerconstants "go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/v11/policy"
	"go.aporeto.io/trireme-lib/v11/utils/cache"
)

var (
	noncePosition = 2
	tokenPosition = 2 + NonceLength
)

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
	compressionType claimsheader.CompressionType
	// compressionTagLength is the length of tags based on compressionType
	compressionTagLength int
	// datapathVersion is the current version of the datapath
	datapathVersion claimsheader.DatapathVersion
}

// JWTClaims captures all the custom  clains
type JWTClaims struct {
	*ConnectionClaims
	jwt.StandardClaims
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
	compressionType := claimsheader.CompressionTypeNone

	if s == nil {
		return nil, errors.New("secrets can not be nil")
	}

	switch s.Type() {
	case secrets.PKICompactType:
		signMethod = jwt.SigningMethodES256
		compressionType = s.(*secrets.CompactPKI).Compressed
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
		compressionTagLength: claimsheader.CompressionTypeToTagLength(compressionType),
		datapathVersion:      claimsheader.DatapathVersion1,
	}, nil
}

// CreateAndSign  creates a new token, attaches an ephemeral key pair and signs with the issuer
// key. It also randomizes the source nonce of the token. It returns back the token and the private key.
func (c *JWTConfig) CreateAndSign(isAck bool, claims *ConnectionClaims, nonce []byte, claimsHeader *claimsheader.ClaimsHeader) (token []byte, err error) {

	// Set the appropriate claims header
	claimsHeader.SetCompressionType(c.compressionType)
	claimsHeader.SetDatapathVersion(c.datapathVersion)

	// Combine the application claims with the standard claims
	allclaims := &JWTClaims{
		&ConnectionClaims{
			T:   claims.T,
			EK:  claims.EK,
			RMT: claims.RMT,
			H:   claimsHeader.ToBytes(),
			ID:  claims.ID,
			CT:  claims.CT,
		},
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(c.ValidityPeriod).Unix(),
		},
	}

	// For backward compatibility, keep the issuer in Ack packets.
	if isAck {
		allclaims.Issuer = c.Issuer
		allclaims.LCL = claims.LCL
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
	var certClaims []string

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

		ackCert, certClaims, _, err = c.secrets.KeyAndClaims(certBytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("invalid public key: %s", err)
		}

		if cachedClaims, cerr := c.tokenCache.Get(string(token)); cerr == nil {
			return cachedClaims.(*ConnectionClaims), nonce, ackCert, nil
		}
	}

	// Parse the JWT token with the public key recovered. If it is an Ack packet
	// use the previous cert.
	jwttoken, err := jwt.ParseWithClaims(string(token), jwtClaims, func(token *jwt.Token) (interface{}, error) { // nolint
		if ackCert != nil {
			return ackCert.(*ecdsa.PublicKey), nil
		}
		if previousCert != nil {
			return previousCert.(*ecdsa.PublicKey), nil
		}
		return nil, fmt.Errorf("Unable to find certificate")
	})

	// If error is returned or the token is not valid, reject it
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to parse token: %s", err)
	}
	if !jwttoken.Valid {
		return nil, nil, nil, errors.New("invalid token")
	}

	if !isAck {
		tags := []string{enforcerconstants.TransmitterLabel + "=" + jwtClaims.ConnectionClaims.ID}
		if jwtClaims.ConnectionClaims.T != nil {
			tags = jwtClaims.ConnectionClaims.T.Tags
		}

		if certClaims != nil {
			tags = append(tags, certClaims...)
		}

		jwtClaims.ConnectionClaims.T = policy.NewTagStoreFromSlice(tags)
	}

	if jwtClaims.ConnectionClaims.H != nil {
		if err := c.verifyClaimsHeader(jwtClaims.ConnectionClaims.H.ToClaimsHeader()); err != nil {
			return nil, nil, nil, err
		}
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

func (c *JWTConfig) verifyClaimsHeader(claimsHeader *claimsheader.ClaimsHeader) error {

	switch {
	case claimsHeader.CompressionType() != c.compressionType:
		return newErrToken(errCompressedTagMismatch)
	case claimsHeader.DatapathVersion() != c.datapathVersion:
		return newErrToken(errDatapathVersionMismatch)
	}

	return nil
}
