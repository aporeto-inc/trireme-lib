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

	log "github.com/Sirupsen/logrus"
)

// ComputeHmac256 computes the HMAC256 of the message
func ComputeHmac256(tags []byte, key []byte) []byte {

	var buffer bytes.Buffer
	binary.Write(&buffer, binary.BigEndian, tags)

	h := hmac.New(sha256.New, key)
	h.Write(buffer.Bytes())

	return h.Sum(nil)

}

// VerifyHmac verifies if the HMAC of the message matches the one provided
func VerifyHmac(tags []byte, expectedMAC []byte, key []byte) bool {
	messageMAC := ComputeHmac256(tags, key)

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
		log.WithFields(log.Fields{
			"package": "crypto",
			"error":   err,
		}).Error("GenerateRandomBytes failed")
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
		log.WithFields(log.Fields{
			"package": "crypto",
			"error":   err,
		}).Error("CreateEphemeralKey failed, returning empty array of bytes")

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
		log.WithFields(log.Fields{
			"package": "crypto",
			"rootPEM": rootPEM,
		}).Debug("AppendCertsFromPEM failed")
		return nil
	}

	return roots

}

// LoadEllipticCurveKey parses and creates an EC key
func LoadEllipticCurveKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)

	if block == nil {
		log.WithFields(log.Fields{
			"package": "crypto",
			"keyPEM":  keyPEM,
		}).Debug("Failed to Parse PEM block")
		return nil, fmt.Errorf("Failed to Parse PEM block")
	}

	// Parse the key
	key, err := x509.ParseECPrivateKey(block.Bytes)

	if err != nil {
		log.WithFields(log.Fields{
			"package": "crypto",
			"block":   block,
		}).Debug("ParseECPrivateKey failed")
		return nil, err
	}

	return key, nil
}

// LoadAndVerifyCertificate parses, validates, and creates a certificate structure from a PEM buffer
// It must be provided with the a CertPool
func LoadAndVerifyCertificate(certPEM []byte, roots *x509.CertPool) (*x509.Certificate, error) {

	// Decode the certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		log.WithFields(log.Fields{
			"package": "crypto",
			"certPEM": certPEM,
		}).Debug("Failed to decode PEM block")
		return nil, fmt.Errorf("Failed to decode PEM block")
	}

	// Create the certificate structure
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		log.WithFields(log.Fields{
			"package":   "crypto",
			"certBlock": certBlock,
			"error":     err,
		}).Debug("Failed to ParseCertificate")
		return nil, err
	}

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		log.WithFields(log.Fields{
			"package":     "crypto",
			"certBlock":   certBlock,
			"error":       err,
			"certificate": cert,
		}).Debug("Failed to verify the option for the certificate ")
		return nil, err
	}

	return cert, nil

}

// LoadAndVerifyECSecrets loads all the certificates and keys to memory in the right data structures
func LoadAndVerifyECSecrets(keyPEM, certPEM, caCertPEM []byte) (key *ecdsa.PrivateKey, cert *x509.Certificate, rootCertPool *x509.CertPool, err error) {

	// Parse the key
	key, err = LoadEllipticCurveKey(keyPEM)

	if err != nil {
		log.WithFields(log.Fields{
			"package": "crypto",
			"keyPEM":  keyPEM,
			"error":   err,
		}).Debug("Failed to LoadEllipticCurveKey")
		return nil, nil, nil, err
	}

	rootCertPool = LoadRootCertificates(caCertPEM)
	if rootCertPool == nil {
		log.WithFields(log.Fields{
			"package":   "crypto",
			"caCertPEM": caCertPEM,
			"error":     err,
		}).Debug("Failed to LoadRootCertificates")
		return nil, nil, nil, fmt.Errorf("Failed to load root certificate pool")
	}

	cert, err = LoadAndVerifyCertificate(certPEM, rootCertPool)
	if err != nil {
		log.WithFields(log.Fields{
			"package":      "crypto",
			"caCertPEM":    certPEM,
			"rootCertPool": rootCertPool,
			"error":        err,
		}).Debug("Failed to LoadAndVerifyCertificate")
		return nil, nil, nil, err
	}

	return key, cert, rootCertPool, nil

}
