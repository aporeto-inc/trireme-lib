package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	mrand "math/rand"
	"sync"
	"time"

	"github.com/ugorji/go/codec"
	"go.aporeto.io/tg/tglib/windowscertbug"
	"go.uber.org/zap"
)

type nonce struct {
	r *mrand.Rand
	sync.Mutex
}

// PublicKey is an intermediate structure to create gobs
type PublicKey struct {
	X *big.Int
	Y *big.Int
}

//Nonce16Byte interface generates 16 byte nonce
type Nonce16Byte interface {
	GenerateNonce16Bytes([]byte)
}

var doOnce sync.Once
var n nonce

// Nonce initializes and returns nonce of type Nonce16Byte.
func Nonce() Nonce16Byte {
	doOnce.Do(func() {
		n.r = mrand.New(mrand.NewSource(time.Now().UnixNano()))
	})

	return &n
}

func (n *nonce) GenerateNonce16Bytes(b []byte) {
	n.Lock()
	low := n.r.Uint64()
	high := n.r.Uint64()
	n.Unlock()

	binary.LittleEndian.PutUint64(b[:8], low)
	binary.LittleEndian.PutUint64(b[8:], high)
}

// ComputeHmac256 computes the HMAC256 of the message
func ComputeHmac256(tags []byte, key []byte) ([]byte, error) {

	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.BigEndian, tags); err != nil {
		return []byte{}, err
	}

	h := hmac.New(sha256.New, key)

	if _, err := h.Write(buffer.Bytes()); err != nil {
		return []byte{}, err
	}

	return h.Sum(nil), nil

}

// VerifyHmac verifies if the HMAC of the message matches the one provided
func VerifyHmac(tags []byte, expectedMAC []byte, key []byte) bool {
	messageMAC, err := ComputeHmac256(tags, key)
	if err != nil {
		return false
	}

	return hmac.Equal(messageMAC, expectedMAC)
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)

	if _, err := rand.Read(b); err != nil {
		zap.L().Debug("GenerateRandomBytes failed", zap.Error(err))
		return nil, err
	}

	s := base64.StdEncoding.EncodeToString(b)

	return []byte(s[:n]), nil
}

// GenerateRandomString returns a URL-safe, base64 encoded
// securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomString(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

// CreateEphemeralKey creates an ephmeral private/public key based on the
// provided public key and the corresponding elliptic curve
func CreateEphemeralKey(curve func() elliptic.Curve, pub *ecdsa.PublicKey) (*ecdsa.PrivateKey, []byte) {

	ephemeral, err := ecdsa.GenerateKey(curve(), rand.Reader)
	if err != nil {
		zap.L().Error("CreateEphemeralKey failed, returning empty array of bytes", zap.Error(err))
		return nil, []byte{}
	}

	ephPub := elliptic.Marshal(pub.Curve, ephemeral.PublicKey.X, ephemeral.PublicKey.Y)

	return ephemeral, ephPub

}

// LoadRootCertificates loads the certificates in the provide PEM buffer in a CertPool
func LoadRootCertificates(rootPEM []byte) *x509.CertPool {

	roots := x509.NewCertPool()

	ok := roots.AppendCertsFromPEM(rootPEM)
	if !ok {
		zap.L().Error("AppendCertsFromPEM failed", zap.ByteString("rootPEM", rootPEM))
		return nil
	}

	return roots

}

// LoadEllipticCurveKey parses and creates an EC key
func LoadEllipticCurveKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("LoadElliticCurveKey bad pem block: %s", string(keyPEM))
	}

	// Parse the key
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// LoadAndVerifyCertificate parses, validates, and creates a certificate structure from a PEM buffer
// It must be provided with the a CertPool
func LoadAndVerifyCertificate(certPEM []byte, roots *x509.CertPool) (*x509.Certificate, error) {

	cert, err := LoadCertificate(certPEM)
	if err != nil {
		return nil, err
	}

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := windowscertbug.VerifyCertificate(cert, opts); err != nil {
		return nil, err
	}

	return cert, nil

}

// LoadAndVerifyECSecrets loads all the certificates and keys to memory in the right data structures
func LoadAndVerifyECSecrets(keyPEM, certPEM, caCertPEM []byte) (key *ecdsa.PrivateKey, cert *x509.Certificate, rootCertPool *x509.CertPool, err error) {

	// Parse the key
	key, err = LoadEllipticCurveKey(keyPEM)
	if err != nil {
		return nil, nil, nil, err
	}

	rootCertPool = LoadRootCertificates(caCertPEM)
	if rootCertPool == nil {
		return nil, nil, nil, errors.New("unable to load root certificate pool")
	}

	cert, err = LoadAndVerifyCertificate(certPEM, rootCertPool)
	if err != nil {
		return nil, nil, nil, err
	}

	return key, cert, rootCertPool, nil

}

// LoadCertificate loads a certificate from a PEM file without verifying
// Should only be used for loading a root CA certificate. It will only read
// the first certificate
func LoadCertificate(certPEM []byte) (*x509.Certificate, error) {

	// Decode the certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("unable to parse pem block: %s", string(certPEM))
	}

	// Create the certificate structure
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

//EncodePublicKeyV1 encodes the public key to a byte slice
func EncodePublicKeyV1(publicKey *ecdsa.PublicKey) []byte {

	p := &PublicKey{X: publicKey.X, Y: publicKey.Y}

	buf := make([]byte, 0, 1400)
	var h codec.Handle = new(codec.CborHandle)
	enc := codec.NewEncoderBytes(&buf, h)

	if err := enc.Encode(p); err != nil {
		return nil
	}

	return buf

}

// DecodePublicKeyV1 decodes the provided public key
func DecodePublicKeyV1(key []byte) (*ecdsa.PublicKey, error) {
	var p PublicKey

	var h codec.Handle = new(codec.CborHandle)

	dec := codec.NewDecoderBytes(key, h)
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     p.X,
		Y:     p.Y,
	}, nil
}

//EncodePublicKeyV2 encodes the public key to a byte slice
func EncodePublicKeyV2(publicKey *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)
}

// DecodePublicKeyV2 decodes the provided public key
func DecodePublicKeyV2(key []byte) (*ecdsa.PublicKey, error) {

	x, y := elliptic.Unmarshal(elliptic.P256(), key)
	if x == nil || y == nil {
		return nil, fmt.Errorf("Failed to decode public key")
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

//EncodePrivateKey encodes the private key to a byte slice.
func EncodePrivateKey(privateKey *ecdsa.PrivateKey) []byte {
	return elliptic.Marshal(privateKey.PublicKey.Curve, privateKey.D, privateKey.PublicKey.X)
}
