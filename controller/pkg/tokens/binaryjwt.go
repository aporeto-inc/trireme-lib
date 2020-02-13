package tokens

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ugorji/go/codec"
	enforcerconstants "go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

// Format of Binary Tokens
//    0             1              2               3               4
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     D     |CT|E| Encoding |    R (reserved)                   |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  | Signature Position           |    nonce                       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   ...                                                         |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   token                                                       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   ...                                                         |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  | Signature                                                     |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   ...                                                         |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  D  [0:6]   - Datapath version
//  CT [6:8]   - Compressed tag type
//  E  [8:9]   - Encryption enabled
//  C  [9:12]  - Codec selector
//  R  [12:32] - Reserved
//  L  [32:48] - Token Length
//  Token bytes (equal to token length)
//  Signature bytes

const (
	binaryNoncePosition = 6
	lengthPosition      = 4
	headerLength        = 4
	nonceLength         = 16
)

type sharedSecret struct {
	key  []byte
	tags []string
}

// BinaryJWTConfig configures the JWT token generator with the standard parameters. One
// configuration is assigned to each server
type BinaryJWTConfig struct {
	// ValidityPeriod  period of the JWT
	ValidityPeriod time.Duration
	// Issuer is the server that issues the JWT
	Issuer string
	// cache test
	tokenCache cache.DataStore
	// sharedKeys is a cache of pre-shared keys.
	sharedKeys cache.DataStore
}

// NewBinaryJWT creates a new JWT token processor
func NewBinaryJWT(validity time.Duration, issuer string) (*BinaryJWTConfig, error) {

	return &BinaryJWTConfig{
		ValidityPeriod: validity,
		Issuer:         issuer,
		tokenCache:     cache.NewCacheWithExpiration("JWTTokenCache", validity),
		sharedKeys:     cache.NewCacheWithExpiration("SharedKeysCache", time.Minute*5),
	}, nil
}

// Decode  takes as argument the JWT token and the certificate of the issuer.
// First it verifies the certificate with the local CA pool, and the decodes
// the JWT if the certificate is trusted
func (c *BinaryJWTConfig) Decode(isAck bool, data []byte, previousCert interface{}, secrets secrets.Secrets) (claims *ConnectionClaims, nonce []byte, publicKey interface{}, err error) {

	if isAck {
		return c.decodeAck(data)
	}

	return c.decodeSyn(data, secrets)
}

// CreateAndSign  creates a new token, attaches an ephemeral key pair and signs with the issuer
// key. It also randomizes the source nonce of the token. It returns back the token and the private key.
func (c *BinaryJWTConfig) CreateAndSign(isAck bool, claims *ConnectionClaims, nonce []byte, header *claimsheader.ClaimsHeader, secrets secrets.Secrets) (token []byte, err error) {

	// Set the appropriate claims header
	header.SetCompressionType(claimsheader.CompressionTypeV1)
	header.SetDatapathVersion(claimsheader.DatapathVersion1)

	if isAck {
		return c.createAckToken(claims, header)
	}

	return c.createSynToken(claims, nonce, header, secrets)
}

// Randomize adds a nonce to an existing token. Returns the nonce
func (c *BinaryJWTConfig) Randomize(token []byte, nonce []byte) (err error) {

	if len(token) < 6+NonceLength {
		return fmt.Errorf("token is too small")
	}

	copy(token[6:], nonce)

	return nil
}

func (c *BinaryJWTConfig) createSynToken(claims *ConnectionClaims, nonce []byte, header *claimsheader.ClaimsHeader, secrets secrets.Secrets) (token []byte, err error) {
	// Combine the application claims with the standard claims.
	// In all cases for Syn/SynAck packets we also transmit our
	// public key.
	allclaims := ConvertToBinaryClaims(claims, c.ValidityPeriod)
	allclaims.SignerKey = secrets.TransmittedKey()

	// This is the hack of backward compatibility that has to be
	// removed.
	pruneTags(allclaims)

	// Encode the claims in a buffer.
	buf, err := encode(allclaims)
	if err != nil {
		return nil, err
	}

	var sig []byte
	if len(claims.RemoteID) == 0 {
		sig, err = c.sign(buf, secrets.EncodingKey().(*ecdsa.PrivateKey))
	} else {
		sig, err = c.signWithSharedKey(buf, claims.RemoteID)
	}
	if err != nil {
		return nil, err
	}

	// Pack and return the token.
	return packToken(header.ToBytes(), nonce, buf, sig), nil
}

func (c *BinaryJWTConfig) createAckToken(claims *ConnectionClaims, header *claimsheader.ClaimsHeader) (token []byte, err error) {

	// Combine the application claims with the standard claims
	allclaims := ConvertToBinaryClaims(claims, c.ValidityPeriod)

	// Encode the claims in a buffer.
	buf, err := encode(allclaims)
	if err != nil {
		return nil, fmt.Errorf("unable to encode claims: %s", err)
	}

	// Sign the buffer with the pre-shared key.
	sig, err := c.signWithSharedKey(buf, claims.RemoteID)
	if err != nil {
		return nil, fmt.Errorf("ack token signature failed: %s", err)
	}

	// Pack and return the token.
	return packToken(header.ToBytes(), nil, buf, sig), nil
}

func (c *BinaryJWTConfig) decodeSyn(data []byte, secrets secrets.Secrets) (claims *ConnectionClaims, nonce []byte, publicKey interface{}, err error) {

	// Unpack the token first.
	header, nonce, token, sig, err := unpackToken(false, data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to unpack token: %s", err)
	}

	// Validate the header version.
	if err := c.verifyClaimsHeader(claimsheader.HeaderBytes(header).ToClaimsHeader()); err != nil {
		return nil, nil, nil, err
	}

	// Decode the claims to a data structure.
	binaryClaims, err := decode(token)
	if err != nil {
		return nil, nil, nil, err
	}

	// Derive the transmitter public key and associated claims. This will also
	// validate that the transmitter key is valid or provide it from a cache.
	// Once it succeeds we know that the public key that was provide is correct.
	publicKey, publicKeyClaims, expTime, err := secrets.KeyAndClaims(binaryClaims.SignerKey)
	if err != nil || publicKey == nil {
		return nil, nil, nil, fmt.Errorf("unable to identify signer key: %s", err)
	}

	// Since we know that the signature is valid, we check if the token is already in
	// the cache and accept it. We do that after the verification, in case the
	// public key has expired and we still have it in the cache.
	if cachedClaims, cerr := c.tokenCache.Get(string(token)); cerr == nil {
		return cachedClaims.(*ConnectionClaims), nonce, publicKey, nil
	}

	// We haven't seen this token again, so we will validate it with the
	// public key and cache it for future calls.

	// First we check if we know RMT attribute is set. This will indicate
	// that this is SynAck packet that carries the remote nonce, and we
	// can use the shared key approach. In the protocol we mandate
	// that RMT in the SynAck is populated since it carries the nonce
	// of the remote.
	if len(binaryClaims.RMT) > 0 {

		binaryClaims.RMT = nil

		key, err := c.deriveSharedKey(binaryClaims.ID, publicKey, publicKeyClaims, expTime, secrets.EncodingKey())
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to generate shared key: %s", err)
		}

		if err := c.verifyWithSharedKey(token, key, sig); err != nil {
			// We need to be cautious here. There is a chance that the remote public key
			// has changed. In this case, we will re-calculate the shared key and try
			// again. We don't have the option of doing that for Ack packets, but at least
			// we can do it here.
			key, err = c.newSharedKey(binaryClaims.ID, publicKey, publicKeyClaims, expTime, secrets.EncodingKey())
			if err != nil {
				return nil, nil, nil, fmt.Errorf("unable to generate shared key: %s", err)
			}

			if err = c.verifyWithSharedKey(token, key, sig); err != nil {
				return nil, nil, nil, fmt.Errorf("unable to verify token with any key: %s", err)
			}
		}
	} else {
		// If the token is not in the cache, we validate the token with the
		// provided and validated public key. We will then add it in the
		// cache for future reference.
		if err := c.verify(token, sig, publicKey.(*ecdsa.PublicKey)); err != nil {
			return nil, nil, nil, fmt.Errorf("unable to verify token: %s", err)
		}

		// We create a new symetric key if we don't already have one.
		_, err := c.newSharedKey(binaryClaims.ID, publicKey, publicKeyClaims, expTime, secrets.EncodingKey())
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to generate shared key: %s", err)
		}
	}

	// Uncommpress the tags and add the public key claims to the tags that
	// we return.
	uncompressTags(binaryClaims, publicKeyClaims)

	connClaims := ConvertToJWTClaims(binaryClaims).ConnectionClaims

	// Cache the token and the token string and the claims and return the
	// connection claims.
	c.tokenCache.AddOrUpdate(string(token), connClaims)

	return connClaims, nonce, publicKey, nil

}

func (c *BinaryJWTConfig) decodeAck(data []byte) (claims *ConnectionClaims, nonce []byte, publicKey interface{}, err error) {

	// Unpack the token first.
	header, nonce, token, sig, err := unpackToken(true, data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to unpack token: %s", err)
	}

	// Validate the header.
	if err := c.verifyClaimsHeader(claimsheader.HeaderBytes(header).ToClaimsHeader()); err != nil {
		return nil, nil, nil, err
	}

	// Decode the claims to a data structure.
	binaryClaims, err := decode(token)
	if err != nil {
		return nil, nil, nil, err
	}

	// Find the shared key. This must already be in the cache and pre-calculated,
	// since we have seen the syn and syn ack packets.
	k, err := c.sharedKeys.Get(binaryClaims.ID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to find shared secret for ID: %s", binaryClaims.ID)
	}
	key := k.(*sharedSecret).key

	// Calculate the signature on the token and compare it with the incoming
	// signature. Since this is simple symetric hashing this is simple.
	if err := c.verifyWithSharedKey(token, key, sig); err != nil {
		return nil, nil, nil, fmt.Errorf("unable to verify ack token: %s", err)
	}

	return ConvertToJWTClaims(binaryClaims).ConnectionClaims, nonce, nil, nil
}

func (c *BinaryJWTConfig) verifyClaimsHeader(h *claimsheader.ClaimsHeader) error {

	if h.CompressionType() != claimsheader.CompressionTypeV1 {
		return newErrToken(errCompressedTagMismatch)
	}

	if h.DatapathVersion() != claimsheader.DatapathVersion1 {
		return newErrToken(errDatapathVersionMismatch)
	}

	return nil
}

func (c *BinaryJWTConfig) sign(buf []byte, key *ecdsa.PrivateKey) ([]byte, error) {

	// Create the hash and use this for the signature. This is a SHA256 hash
	// of the token.
	h, err := hash(buf, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to sign header on ack packet: %s", err)
	}

	// Sign the hash with the private key using the ECDSA algorithm
	// and properly format the resulting signature.
	r, s, err := ecdsa.Sign(rand.Reader, key, h)
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

func (c *BinaryJWTConfig) verify(buf []byte, sig []byte, key *ecdsa.PublicKey) error {

	if len(sig) != 64 {
		return fmt.Errorf("invalid signature length: %d", len(sig))
	}

	r := big.NewInt(0).SetBytes(sig[:32])
	s := big.NewInt(0).SetBytes(sig[32:])

	// Create the hash and use this for the signature. This is a SHA256 hash
	// of the token.
	h, err := hash(buf, nil)
	if err != nil {
		return fmt.Errorf("unable to sign header on ack packet: %s", err)
	}

	if verifyStatus := ecdsa.Verify(key, h, r, s); verifyStatus {
		return nil
	}

	return fmt.Errorf("invalid signature")
}

func (c *BinaryJWTConfig) signWithSharedKey(buf []byte, id string) ([]byte, error) {

	s, err := c.sharedKeys.Get(id)
	if err != nil {
		return nil, fmt.Errorf("shared secret not found")
	}

	sk, ok := s.(*sharedSecret)
	if !ok {
		return nil, fmt.Errorf("invalid secret")
	}

	return hash(buf, sk.key)
}

func (c *BinaryJWTConfig) verifyWithSharedKey(buf []byte, key []byte, sig []byte) error {

	ps, err := hash(buf, key)
	if err != nil {
		return fmt.Errorf("unable to hash toke in synack: %s", err)
	}

	if !bytes.Equal(ps, sig) {
		return fmt.Errorf("unable to verify token with shared secret: they don't match %d %d ", len(ps), len(sig))
	}

	return nil
}

func (c *BinaryJWTConfig) deriveSharedKey(id string, publicKey interface{}, publicKeyClaims []string, expTime time.Time, privateKey interface{}) ([]byte, error) {

	// We try to find the remote in the cache
	k, err := c.sharedKeys.Get(id)
	if err != nil {
		// We don't have it in the cache. Let's create a new shared key.
		return c.newSharedKey(id, publicKey, publicKeyClaims, expTime, privateKey)
	}
	// Key is already found in the cache.
	return k.(*sharedSecret).key, nil
}

func (c *BinaryJWTConfig) newSharedKey(id string, publicKey interface{}, publicKeyClaims []string, expTime time.Time, privateKey interface{}) ([]byte, error) {

	key, err := symmetricKey(privateKey, publicKey)
	if err != nil {
		return nil, err
	}

	// Add it in the cache
	c.sharedKeys.AddOrUpdate(id, &sharedSecret{
		key:  key,
		tags: publicKeyClaims,
	})

	// if the token expires before our default validity, update the timer
	// so that we expire it no longer than its validity.
	if time.Now().Add(c.ValidityPeriod).After(expTime) {
		if err := c.sharedKeys.SetTimeOut(id, time.Until(expTime)); err != nil {
			zap.L().Warn("Failed to update cache validity for token", zap.Error(err))
		}
	}

	return key, nil
}

func encode(c *BinaryJWTClaims) ([]byte, error) {
	// Encode and sign the token
	buf := make([]byte, 0, 1400)
	var h codec.Handle = new(codec.CborHandle)
	enc := codec.NewEncoderBytes(&buf, h)

	if err := enc.Encode(c); err != nil {
		return nil, fmt.Errorf("unable to encode message: %s", err)
	}

	return buf, nil
}

func decode(buf []byte) (*BinaryJWTClaims, error) {
	// Decode the token into a structure.
	binaryClaims := &BinaryJWTClaims{}
	var h codec.Handle = new(codec.CborHandle)

	dec := codec.NewDecoderBytes(buf, h)
	if err := dec.Decode(binaryClaims); err != nil {
		return nil, fmt.Errorf("decoding failed: %s", err)
	}

	if binaryClaims.ExpiresAt < time.Now().Unix() {
		return nil, fmt.Errorf("token is expired since: %s", time.Unix(binaryClaims.ExpiresAt, 0))
	}

	return binaryClaims, nil
}

func packToken(header, nonce, token, sig []byte) []byte {

	binaryTokenPosition := binaryNoncePosition + len(nonce)
	sigPosition := binaryTokenPosition + len(token)

	// Token is the concatenation of
	// [Position of Signature] [nonce] [token] [signature]
	data := make([]byte, sigPosition+len(sig))

	// Header bytes
	copy(data[0:headerLength], header)

	// Length of token
	binary.BigEndian.PutUint16(data[lengthPosition:], uint16(sigPosition))

	// nonce not required for ack packets
	if len(nonce) > 0 {
		copy(data[binaryNoncePosition:], nonce)
	}

	// token
	copy(data[binaryTokenPosition:], token)

	// signature
	copy(data[sigPosition:], sig)

	return data
}

// unpackToken returns nonce, token, signature or error if something fails
func unpackToken(isAck bool, data []byte) ([]byte, []byte, []byte, []byte, error) {

	// We must have enough data to read the length.
	if len(data) < binaryNoncePosition {
		return nil, nil, nil, nil, fmt.Errorf("not enough data")
	}

	header := data[:lengthPosition]

	sigPosition := int(binary.BigEndian.Uint16(data[lengthPosition : lengthPosition+2]))

	// The token must be long enough to have at least 1 byte of signature.
	if len(data) < sigPosition+1 {
		return nil, nil, nil, nil, fmt.Errorf("no signature in the token")
	}

	var nonce []byte
	if !isAck {
		nonce = make([]byte, 16)
		copy(nonce, data[binaryNoncePosition:binaryNoncePosition+nonceLength])
	}

	// Only if nonce is found do we need to advance. So, use the
	// actual length of the nonce and not just a constant here.
	token := data[binaryNoncePosition+len(nonce) : sigPosition]

	sig := data[sigPosition:]

	return header, nonce, token, sig, nil
}

func hash(buf []byte, key []byte) ([]byte, error) {

	hasher := crypto.SHA256.New()
	if _, err := hasher.Write(buf); err != nil {
		return nil, fmt.Errorf("unable to hash data structure: %s", err)
	}

	return hasher.Sum(key), nil
}

// symmetricKey returns a symmetric key for encryption
func symmetricKey(privateKey interface{}, remotePublic interface{}) ([]byte, error) {

	c := elliptic.P256()

	x, _ := c.ScalarMult(remotePublic.(*ecdsa.PublicKey).X, remotePublic.(*ecdsa.PublicKey).Y, privateKey.(*ecdsa.PrivateKey).D.Bytes())

	return hash(x.Bytes(), nil)
}

func pruneTags(claims *BinaryJWTClaims) {
	// Handling compression here. If we need to use compression, we will copy
	// the claims to the C claim and remove all the other fields.
	for _, t := range claims.T {
		if strings.HasPrefix(t, enforcerconstants.TransmitterLabel) {
			claims.ID = t[len(enforcerconstants.TransmitterLabel)+1:]
			break
		}
	}
	claims.T = nil
}

func uncompressTags(binaryClaims *BinaryJWTClaims, publicKeyClaims []string) {

	binaryClaims.T = append(binaryClaims.CT, enforcerconstants.TransmitterLabel+"="+binaryClaims.ID)
	if len(publicKeyClaims) > 0 {
		binaryClaims.T = append(binaryClaims.T, publicKeyClaims...)
	}
}
