package tokens

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/ugorji/go/codec"
	enforcerconstants "go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

// BinaryJWTConfig configures the JWT token generator with the standard parameters. One
// configuration is assigned to each server
type BinaryJWTConfig struct {
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

// NewBinaryJWT creates a new JWT token processor
func NewBinaryJWT(validity time.Duration, issuer string, s secrets.Secrets) (*BinaryJWTConfig, error) {

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

	return &BinaryJWTConfig{
		ValidityPeriod:       validity,
		Issuer:               issuer,
		signMethod:           signMethod,
		secrets:              s,
		tokenCache:           cache.NewCacheWithExpiration("JWTTokenCache", time.Millisecond*2000),
		compressionType:      compressionType,
		compressionTagLength: claimsheader.CompressionTypeToTagLength(compressionType),
		datapathVersion:      claimsheader.DatapathVersion1,
	}, nil
}

// CreateAndSign  creates a new token, attaches an ephemeral key pair and signs with the issuer
// key. It also randomizes the source nonce of the token. It returns back the token and the private key.
func (c *BinaryJWTConfig) CreateAndSign(isAck bool, claims *ConnectionClaims, nonce []byte, claimsHeader *claimsheader.ClaimsHeader) (token []byte, err error) {

	// Combine the application claims with the standard claims
	allclaims := ConvertToBinaryClaims(claims, c.ValidityPeriod)

	if !isAck {
		allclaims.SignerKey = c.secrets.TransmittedKey()

		// Handling compression here. If we need to use compression, we will copy
		// the claims to the C claim and remove all the other fields.
		tags := allclaims.T
		allclaims.T = nil
		for _, t := range tags {
			if strings.HasPrefix(t, enforcerconstants.TransmitterLabel) {
				allclaims.ID = t[len(enforcerconstants.TransmitterLabel)+1:]
			} else {
				allclaims.C = t
			}
		}
		zap.L().Debug("claims (post)", zap.Reflect("all", allclaims))
	} else {
		nonce = nil
	}

	// Set the appropriate claims header
	claimsHeader.SetCompressionType(c.compressionType)
	claimsHeader.SetDatapathVersion(c.datapathVersion)
	allclaims.H = claimsHeader.ToBytes()

	// Encode and sign the token
	buf := make([]byte, 0, 1400)
	var h codec.Handle = new(codec.CborHandle)
	enc := codec.NewEncoderBytes(&buf, h)

	if err = enc.Encode(allclaims); err != nil {
		return nil, fmt.Errorf("unable to encode message: %s", err)
	}

	var sig []byte
	if isAck {
		sig, err = hash(buf)
	} else {
		sig, err = c.sign(buf, c.secrets.EncodingKey().(*ecdsa.PrivateKey))
	}
	if err != nil {
		return nil, err
	}

	// Pack and return the token.
	return packToken(nonce, buf, sig), nil

}

func packToken(nonce, buf, sig []byte) []byte {

	// Token is the concatenation of
	// [Position of Signature] [nonce] [token] [signature]
	token := make([]byte, len(buf)+len(nonce)+len(sig)+2)

	binary.BigEndian.PutUint16(token[0:2], uint16(len(nonce)+len(buf)+2))
	if len(nonce) > 0 {
		copy(token[2:], nonce)
	}
	copy(token[2+len(nonce):], buf)
	copy(token[2+len(nonce)+len(buf):], sig)

	return token
}

// unpackToken returns nonce, token, signature or error if something fails
func unpackToken(isAck bool, data []byte) ([]byte, []byte, []byte, error) {

	// We must have enough data to read the length.
	if len(data) < 2 {
		return nil, nil, nil, fmt.Errorf("not enough data")
	}
	sigPosition := int(binary.BigEndian.Uint16(data[0:2]))

	// The token must be long enough to have at least 1 byte of signature.
	if len(data) < sigPosition+1 {
		return nil, nil, nil, fmt.Errorf("no signature in the token")
	}

	var nonce []byte
	if !isAck {
		nonce = data[2 : 2+NonceLength]
	}

	token := data[2+len(nonce) : sigPosition]
	sig := data[sigPosition:]
	return nonce, token, sig, nil
}

// Decode  takes as argument the JWT token and the certificate of the issuer.
// First it verifies the certificate with the local CA pool, and the decodes
// the JWT if the certificate is trusted
func (c *BinaryJWTConfig) Decode(isAck bool, data []byte, previousCert interface{}) (claims *ConnectionClaims, nonce []byte, publicKey interface{}, err error) {

	var ackCert interface{}
	var certClaims []string

	// Unpack the token first.
	nonce, token, sig, err := unpackToken(isAck, data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to unpack token: %s", err)
	}

	// Decode the token into a structure.
	jwtClaims := &BinaryJWTClaims{}
	var h codec.Handle = new(codec.CborHandle)
	dec := codec.NewDecoderBytes(token, h)
	if err := dec.Decode(jwtClaims); err != nil {
		return nil, nil, nil, fmt.Errorf("unable to decode incoming token: %s", err)
	}

	// If it is not an Ack packet, parse it for the signing key.
	if !isAck {
		ackCert, certClaims, err = c.secrets.KeyAndClaims(jwtClaims.SignerKey)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to identify signer key: %s", err)
		}
	}

	// Look it up in the cache. If we have already validated it, return immediately.
	if cachedClaims, cerr := c.tokenCache.Get(string(token)); cerr == nil {
		return cachedClaims.(*ConnectionClaims), nonce, ackCert, nil
	}

	// Validate the header.
	if jwtClaims.H != nil {
		if err := c.verifyClaimsHeader(jwtClaims.H.ToClaimsHeader()); err != nil {
			return nil, nil, nil, err
		}
	}

	// Figure out which key to use.
	if ackCert == nil && previousCert == nil {
		return nil, nil, nil, fmt.Errorf("public key not available")
	}

	if ackCert != nil {
		publicKey = ackCert.(*ecdsa.PublicKey)
	}
	if previousCert != nil {
		publicKey = previousCert.(*ecdsa.PublicKey)
	}

	// Validate the token.
	if !isAck {
		if err := c.verify(token, sig, publicKey.(*ecdsa.PublicKey)); err != nil {
			return nil, nil, nil, fmt.Errorf("unable to verify token: %s", err)
		}
	} else {
		ps, err := hash(token)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to verify token: %s", err)
		}
		if bytes.Compare(ps, sig) != 0 {
			fmt.Println("Faield")
			return nil, nil, nil, fmt.Errorf("unable to verify token: %s", err)
		}
	}

	if !isAck {

		// Handling of compressed tags in a backward compatible manner. If there are claims
		// arriving in the compressed field then we append them to the tags.

		tags := []string{enforcerconstants.TransmitterLabel + "=" + jwtClaims.ID}

		if certClaims != nil {
			tags = append(tags, certClaims...)
		}

		compressedClaims, err := base64.StdEncoding.DecodeString(jwtClaims.C)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("invalid claims")
		}

		if len(compressedClaims)%c.compressionTagLength != 0 {
			return nil, nil, nil, fmt.Errorf("invalid claims length. compression mismatch %d/%d", len(compressedClaims), c.compressionTagLength)
		}

		for i := 0; i < len(compressedClaims); i = i + c.compressionTagLength {
			tags = append(tags, base64.StdEncoding.EncodeToString(compressedClaims[i:i+c.compressionTagLength]))
		}

		jwtClaims.T = tags

		zap.L().Debug("claims (post)", zap.Reflect("jwt", jwtClaims))
	}

	connClaims := ConvertToJWTClaims(jwtClaims).ConnectionClaims
	c.tokenCache.AddOrUpdate(string(token), connClaims)

	return connClaims, nonce, publicKey, nil
}

// Randomize adds a nonce to an existing token. Returns the nonce
func (c *BinaryJWTConfig) Randomize(token []byte, nonce []byte) (err error) {

	if len(token) < 2+NonceLength {
		return fmt.Errorf("token is too small")
	}

	copy(token[2:], nonce)

	return nil
}

func (c *BinaryJWTConfig) verifyClaimsHeader(claimsHeader *claimsheader.ClaimsHeader) error {

	switch {
	case claimsHeader.CompressionType() != c.compressionType:
		return newErrToken(errCompressedTagMismatch)
	case claimsHeader.DatapathVersion() != c.datapathVersion:
		return newErrToken(errDatapathVersionMismatch)
	}

	return nil
}

func (c *BinaryJWTConfig) sign(hash []byte, key *ecdsa.PrivateKey) ([]byte, error) {

	r, s, err := ecdsa.Sign(rand.Reader, c.secrets.EncodingKey().(*ecdsa.PrivateKey), hash)
	if err != nil {
		return nil, fmt.Errorf("unable to sign token data: %s", err)
	}

	curveBits := key.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	// We serialize the outpus (r and s) into big-endian byte arrays and pad
	// them with zeros on the left to make sure the sizes work out. Both arrays
	// must be keyBytes long, and the output must be 2*keyBytes long.
	tokenBytes := make([]byte, 2*keyBytes)

	rBytes := r.Bytes()
	copy(tokenBytes[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	copy(tokenBytes[2*keyBytes-len(sBytes):], sBytes)

	return tokenBytes, nil
}

func (c *BinaryJWTConfig) verify(hash []byte, sig []byte, key *ecdsa.PublicKey) error {

	if len(sig) != 64 {
		return fmt.Errorf("invalid signature length: %d", len(sig))
	}

	r := big.NewInt(0).SetBytes(sig[:32])
	s := big.NewInt(0).SetBytes(sig[32:])

	if verifyStatus := ecdsa.Verify(key, hash, r, s); verifyStatus == true {
		return nil
	}

	return fmt.Errorf("invalid signature")
}

var (
	badsecret = []byte("1234567890123456")
)

func hash(buf []byte) ([]byte, error) {

	hasher := crypto.SHA256.New()
	if _, err := hasher.Write(buf); err != nil {
		return nil, fmt.Errorf("unable to hash data structure: %s", err)
	}

	return hasher.Sum(badsecret), nil
}
