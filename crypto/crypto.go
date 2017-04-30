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
	"fmt"

	"go.uber.org/zap"
)

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
	_, err := rand.Read(b)

	if err != nil {
		zap.L().Debug("GenerateRandomBytes failed", zap.Error(err))
		return nil, err
	}

	return b, nil
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
		return nil, fmt.Errorf("Failed to Parse PEM block")
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

	if _, err := cert.Verify(opts); err != nil {
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
		return nil, nil, nil, fmt.Errorf("Failed to load root certificate pool")
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
		return nil, fmt.Errorf("Failed to decode PEM block")
	}

	// Create the certificate structure
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
