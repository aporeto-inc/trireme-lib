package tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ugorji/go/codec"
	enforcerconstants "go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/ephemeralkeys"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pkiverifier"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cache"
	localcrypto "go.aporeto.io/enforcerd/trireme-lib/utils/crypto"
)

// To generate the codecs,
// codecgen -o binarycodec.go binaryjwtclaimtypes.go

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
	binaryNoncePosition   = 6
	lengthPosition        = 4
	headerLength          = 4
	sharedKeyCacheTimeout = 5 * time.Minute
)

//ClaimsEncodedBufSize is the size of maximum buffer that is required
//for claims to be serialized into
const ClaimsEncodedBufSize = 1400

// AckPattern is added in SYN and ACK tokens.
var AckPattern = []byte("PANWIDENTITY")
var sha256KeyLength int = 32

type sharedKeyStruct struct {
	sharedKeys map[string][]byte
	sync.RWMutex
}

func (s *sharedKeyStruct) Get(key string) []byte {

	s.RLock()

	if val, ok := s.sharedKeys[key]; ok {
		s.RUnlock()
		return val
	}

	s.RUnlock()
	return nil
}

func (s *sharedKeyStruct) Put(key string, val []byte) {

	s.Lock()
	s.sharedKeys[key] = val
	s.Unlock()

	time.AfterFunc(sharedKeyCacheTimeout, func() {
		s.Lock()
		delete(s.sharedKeys, key)
		s.Unlock()
	})
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
	// sharedKey is a cache of pre-shared keys.
	sharedKeys *sharedKeyStruct
}

// NewBinaryJWT creates a new JWT token processor
func NewBinaryJWT(validity time.Duration, issuer string) (*BinaryJWTConfig, error) {

	return &BinaryJWTConfig{
		ValidityPeriod: validity,
		Issuer:         issuer,
		tokenCache:     cache.NewCacheWithExpiration("JWTTokenCache", validity),
		sharedKeys:     &sharedKeyStruct{sharedKeys: map[string][]byte{}},
	}, nil
}

// DecodeSyn takes as argument the JWT token and the certificate of the issuer.
// First it verifies the certificate with the local CA pool, and the decodes
// the JWT if the certificate is trusted
func (c *BinaryJWTConfig) DecodeSyn(isSynAck bool, data []byte, privateKey *ephemeralkeys.PrivateKey, secrets secrets.Secrets, connClaims *ConnectionClaims) ([]byte, *claimsheader.ClaimsHeader, []byte, *pkiverifier.PKIControllerInfo, bool, error) {
	header, nonce, token, sig, err := unpackToken(false, data)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	// Parse the claims header.
	claimsHeader := claimsheader.HeaderBytes(header).ToClaimsHeader()

	// Validate the header version.
	if err := c.verifyClaimsHeader(claimsHeader); err != nil {
		return nil, nil, nil, nil, false, err
	}

	// Decode the claims to a data structure.
	binaryClaims, err := decode(token)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}

	//Process 314 Protocol
	if len(binaryClaims.DEK) == 0 {
		secretKey, controller, err := c.process314Protocol(isSynAck, token, secrets, connClaims, binaryClaims, sig)
		return secretKey, claimsHeader, nonce, controller, true, err
	}

	//Process 500 Protocol
	secretKey, controller, err := c.process500Protocol(isSynAck, token, privateKey, secrets, connClaims, binaryClaims, sig)

	return secretKey, claimsHeader, nonce, controller, false, err
}

// DecodeAck decodes the ack packet token
func (c *BinaryJWTConfig) DecodeAck(proto314 bool, secretKey []byte, data []byte, connClaims *ConnectionClaims) error {
	// Unpack the token first.
	header, _, token, sig, err := unpackToken(true, data)
	if err != nil {
		return err
	}

	// Parse the claims header.
	claimsHeader := claimsheader.HeaderBytes(header).ToClaimsHeader()

	// Validate the header.
	if err := c.verifyClaimsHeader(claimsHeader); err != nil {
		return err
	}

	// Decode the claims to a data structure.
	binaryClaims, err := decode(token)
	if err != nil {
		return err
	}

	if proto314 {
		// Calculate the signature on the token and compare it with the incoming
		// signature. Since this is simple symetric hashing this is simple.
		if err := c.verifyWithSharedKey314(token, secretKey, sig); err != nil {
			return err
		}
	} else {
		if err := c.verifyWithSharedKey500(token, secretKey, sig[0:sha256KeyLength]); err != nil {
			return err
		}
	}

	CopyToConnectionClaims(binaryClaims, connClaims)
	return nil
}

//CreateSynToken creates the token which is attached to the tcp syn packet.
func (c *BinaryJWTConfig) CreateSynToken(claims *ConnectionClaims, encodedBuf []byte, nonce []byte, header *claimsheader.ClaimsHeader, secrets secrets.Secrets) ([]byte, error) {
	// Set the appropriate claims header
	header.SetCompressionType(claimsheader.CompressionTypeV1)
	header.SetDatapathVersion(claimsheader.DatapathVersion1)

	// Combine the application claims with the standard claims.
	// In all cases for Syn/SynAck packets we also transmit our
	// public key.
	allclaims := ConvertToBinaryClaims(claims, c.ValidityPeriod)
	allclaims.SignerKey = secrets.TransmittedKey()

	// Encode the claims in a buffer.
	err := encode(allclaims, &encodedBuf)
	if err != nil {
		return nil, logError(ErrTokenEncodeFailed, err.Error())
	}

	var sig []byte

	encodedBuf = append(encodedBuf, AckPattern...)

	sig, err = c.sign(encodedBuf, secrets.EncodingKey().(*ecdsa.PrivateKey))

	if err != nil {
		return nil, err
	}

	// Pack and return the token.
	return packToken(header.ToBytes(), nonce, encodedBuf, sig), nil
}

//CreateSynAckToken creates syn/ack token which is attached to the syn/ack packet.
func (c *BinaryJWTConfig) CreateSynAckToken(proto314 bool, claims *ConnectionClaims, encodedBuf []byte, nonce []byte, header *claimsheader.ClaimsHeader, secrets secrets.Secrets, secretKey []byte) ([]byte, error) {

	// Set the appropriate claims header
	header.SetCompressionType(claimsheader.CompressionTypeV1)
	header.SetDatapathVersion(claimsheader.DatapathVersion1)

	// Combine the application claims with the standard claims.
	// In all cases for Syn/SynAck packets we also transmit our
	// public key.
	allclaims := ConvertToBinaryClaims(claims, c.ValidityPeriod)
	allclaims.SignerKey = secrets.TransmittedKey()

	// Encode the claims in a buffer.
	err := encode(allclaims, &encodedBuf)
	if err != nil {
		return nil, logError(ErrTokenEncodeFailed, err.Error())
	}

	var sig []byte

	encodedBuf = append(encodedBuf, AckPattern...)

	if proto314 {
		sig, err = hash314(encodedBuf, secretKey)
		if err != nil {
			return nil, err
		}
	} else {
		sig, err = hash500(encodedBuf, secretKey)
		if err != nil {
			return nil, err
		}
	}

	// Pack and return the token.
	return packToken(header.ToBytes(), nonce, encodedBuf, sig), nil
}

// Randomize puts the random nonce in the syn token
func (c *BinaryJWTConfig) Randomize(token []byte, nonce []byte) error {

	if len(token) < 6+NonceLength {
		return logError(ErrTokenTooSmall, "token is too small")
	}

	copy(token[6:], nonce)

	return nil
}

//CreateAckToken creates ack token which is attached to the ack packet.
func (c *BinaryJWTConfig) CreateAckToken(proto314 bool, secretKey []byte, claims *ConnectionClaims, encodedBuf []byte, header *claimsheader.ClaimsHeader) ([]byte, error) {

	var pad []byte
	// Combine the application claims with the standard claims
	allclaims := ConvertToBinaryClaims(claims, c.ValidityPeriod)

	// Encode the claims in a buffer.
	err := encode(allclaims, &encodedBuf)
	if err != nil {
		return nil, logError(ErrTokenEncodeFailed, err.Error())
	}
	encodedBuf = append(encodedBuf, AckPattern...)

	var sig []byte
	// Sign the buffer with the pre-shared key.
	if proto314 {
		sig, err = hash314(encodedBuf, secretKey)
		if err != nil {
			return nil, err
		}
		pad = sig
	} else {
		pad = make([]byte, 64)
		sig, err = hash500(encodedBuf, secretKey)
		if err != nil {
			return nil, err
		}
		copy(pad, sig)
	}

	// Pack and return the token.
	return packToken(header.ToBytes(), nil, encodedBuf, pad), nil
}

func (c *BinaryJWTConfig) verifyClaimsHeader(h *claimsheader.ClaimsHeader) error {

	if h.CompressionType() != claimsheader.CompressionTypeV1 {
		return ErrCompressedTagMismatch

	}

	if h.DatapathVersion() != claimsheader.DatapathVersion1 {
		return ErrDatapathVersionMismatch
	}

	return nil
}

// Sign takes in a slice of bytes and a private key, and returns a ecdsa signature.
func (c *BinaryJWTConfig) Sign(buf []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	return c.sign(buf, key)
}

func (c *BinaryJWTConfig) sign(buf []byte, key *ecdsa.PrivateKey) ([]byte, error) {

	// Create the hash and use this for the signature. This is a SHA256 hash
	// of the token.
	h, err := hash500(buf, nil)
	if err != nil {
		return nil, logError(ErrTokenHashFailed, err.Error())
	}

	// Sign the hash with the private key using the ECDSA algorithm
	// and properly format the resulting signature.
	r, s, err := ecdsa.Sign(rand.Reader, key, h)
	if err != nil {
		return nil, logError(ErrTokenSignFailed, err.Error())
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
		return ErrInvalidSignature
	}

	r := big.NewInt(0).SetBytes(sig[:32])
	s := big.NewInt(0).SetBytes(sig[32:])

	// Create the hash and use this for the signature. This is a SHA256 hash
	// of the token.
	h, err := hash500(buf, nil)
	if err != nil {
		return logError(ErrTokenHashFailed, err.Error())
	}

	if verifyStatus := ecdsa.Verify(key, h, r, s); verifyStatus {
		return nil
	}

	return ErrInvalidSignature
}

func (c *BinaryJWTConfig) getSecretKey(privateKey *ephemeralkeys.PrivateKey, remotePublicKeyString string, isV1Proto bool) ([]byte, error) {

	var remotePublicKey *ecdsa.PublicKey
	var err error

	hashKey := privateKey.PrivateKeyString + remotePublicKeyString

	secretKey := c.sharedKeys.Get(hashKey)

	if secretKey != nil {
		return secretKey, nil
	}

	if isV1Proto {
		remotePublicKey, err = localcrypto.DecodePublicKeyV1([]byte(remotePublicKeyString))
		if err != nil {
			return nil, err
		}
	} else {
		remotePublicKey, err = localcrypto.DecodePublicKeyV2([]byte(remotePublicKeyString))
		if err != nil {
			return nil, err
		}
	}

	if secretKey, err = symmetricKey(privateKey.PrivateKey, remotePublicKey); err != nil {
		return nil, err
	}

	c.sharedKeys.Put(hashKey, secretKey)

	return secretKey, nil
}

func encode(c *BinaryJWTClaims, buf *[]byte) error {
	// Encode and sign the token
	if cap(*buf) != ClaimsEncodedBufSize {
		return fmt.Errorf("Not enough space in byte slice")
	}

	var h codec.Handle = new(codec.CborHandle)
	enc := codec.NewEncoderBytes(buf, h)
	if err := enc.Encode(c); err != nil {
		return fmt.Errorf("unable to encode message: %s", err)
	}

	return nil
}

func decode(buf []byte) (*BinaryJWTClaims, error) {
	// Decode the token into a structure.
	binaryClaims := &BinaryJWTClaims{}
	var h codec.Handle = new(codec.CborHandle)

	dec := codec.NewDecoderBytes(buf, h)

	if err := dec.Decode(binaryClaims); err != nil {
		return nil, logError(ErrTokenDecodeFailed, err.Error())
	}

	if binaryClaims.ExpiresAt < time.Now().Unix() {
		return nil, logError(ErrTokenExpired, fmt.Sprintf("token is expired since: %s", time.Unix(binaryClaims.ExpiresAt, 0)))
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
		return nil, nil, nil, nil, ErrInvalidTokenLength
	}

	header := make([]byte, headerLength)
	copy(header, data[:lengthPosition])

	sigPosition := int(binary.BigEndian.Uint16(data[lengthPosition : lengthPosition+2]))
	// The token must be long enough to have at least 1 byte of signature.
	if len(data) < sigPosition+1 || sigPosition == 0 {
		return nil, nil, nil, nil, ErrMissingSignature
	}

	var nonce []byte

	if !isAck {
		nonce = make([]byte, 16)
		copy(nonce, data[binaryNoncePosition:binaryNoncePosition+NonceLength])
	}

	// Only if nonce is found do we need to advance. So, use the
	// actual length of the nonce and not just a constant here.
	token := data[binaryNoncePosition+len(nonce) : sigPosition]

	sig := data[sigPosition:]
	return header, nonce, token, sig, nil
}

// symmetricKey returns a symmetric key for encryption
func symmetricKey(privateKey *ecdsa.PrivateKey, remotePublic *ecdsa.PublicKey) ([]byte, error) {

	c := elliptic.P256()

	x, _ := c.ScalarMult(remotePublic.X, remotePublic.Y, privateKey.D.Bytes())

	return hash500(x.Bytes(), nil)
}

func uncompressTags(binaryClaims *BinaryJWTClaims, publicKeyClaims []string) {

	binaryClaims.T = append(binaryClaims.CT, enforcerconstants.TransmitterLabel+"="+binaryClaims.ID)

	for _, pc := range publicKeyClaims {

		if len(pc) <= claimsheader.CompressedTagLengthV1 {
			binaryClaims.T = append(binaryClaims.T, pc)
			continue
		}

		binaryClaims.T = append(binaryClaims.T, pc[:claimsheader.CompressedTagLengthV1])
	}
}
