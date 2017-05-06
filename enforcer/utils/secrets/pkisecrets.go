package secrets

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/crypto"
)

// PKISecrets holds all PKI information
type PKISecrets struct {
	PrivateKeyPEM    []byte
	PublicKeyPEM     []byte
	AuthorityPEM     []byte
	CertificateCache map[string]*ecdsa.PublicKey
	privateKey       *ecdsa.PrivateKey
	publicKey        *x509.Certificate
	certPool         *x509.CertPool
}

// NewPKISecrets creates new secrets for PKI implementations
func NewPKISecrets(keyPEM, certPEM, caPEM []byte, certCache map[string]*ecdsa.PublicKey) (*PKISecrets, error) {
	key, cert, caCertPool, err := crypto.LoadAndVerifyECSecrets(keyPEM, certPEM, caPEM)
	if err != nil {
		return nil, fmt.Errorf("Invalid certificates")
	}

	p := &PKISecrets{
		PrivateKeyPEM:    keyPEM,
		PublicKeyPEM:     certPEM,
		AuthorityPEM:     caPEM,
		CertificateCache: certCache,
		privateKey:       key,
		publicKey:        cert,
		certPool:         caCertPool,
	}

	return p, nil
}

// Type implements the interface Secrets
func (p *PKISecrets) Type() PrivateSecretsType {
	return PKIType
}

// EncodingKey returns the private key
func (p *PKISecrets) EncodingKey() interface{} {
	return p.privateKey
}

// PublicKey returns the public key
func (p *PKISecrets) PublicKey() interface{} {
	return p.publicKey
}

// DecodingKey returns the public key
func (p *PKISecrets) DecodingKey(server string, ackCert interface{}, prevCert interface{}) (interface{}, error) {

	// If we have a cache of certificates, just look there
	if p.CertificateCache != nil {
		cert, ok := p.CertificateCache[server]

		if !ok {
			return nil, fmt.Errorf("No certificate in cache for server %s", server)
		}

		return cert, nil
	}

	// If we have an inband certificate, return this one
	if ackCert != nil {
		return ackCert.(*x509.Certificate).PublicKey.(*ecdsa.PublicKey), nil
	}

	// Otherwise, return the prevCert
	if prevCert != nil {
		return prevCert, nil
	}

	return nil, fmt.Errorf("No valid certificate")
}

// VerifyPublicKey verifies if the inband public key is correct.
func (p *PKISecrets) VerifyPublicKey(pkey []byte) (interface{}, error) {
	decodedCert, err := crypto.LoadAndVerifyCertificate(pkey, p.certPool)

	if err != nil {
		return nil, err
	}

	return decodedCert, nil
}

// TransmittedKey returns the PEM of the public key in the case of PKI
// if there is no certificate cache configured
func (p *PKISecrets) TransmittedKey() []byte {
	return p.PublicKeyPEM
}

// AckSize returns the default size of an ACK packet
func (p *PKISecrets) AckSize() uint32 {
	return uint32(336)
}

// PublicKeyAdd validates the parameter certificate.
// If valid, the corresponding key is added in the PublicKeyCache.
// If Invalid, an error is returned.
func (p *PKISecrets) PublicKeyAdd(host string, newCert []byte) error {

	cert, err := crypto.LoadAndVerifyCertificate(newCert, p.certPool)
	if err != nil {
		return fmt.Errorf("Error loading new Cert: %s", err)
	}

	zap.L().Debug("Adding Cert for host", zap.String("host", host))

	p.CertificateCache[host] = cert.PublicKey.(*ecdsa.PublicKey)
	return nil
}

// AuthPEM returns the Certificate Authority PEM
func (p *PKISecrets) AuthPEM() []byte {
	return p.AuthorityPEM
}

// TransmittedPEM returns the PEM certificate that is transmitted
func (p *PKISecrets) TransmittedPEM() []byte {
	return p.PublicKeyPEM
}

// EncodingPEM returns the certificate PEM that is used for encoding
func (p *PKISecrets) EncodingPEM() []byte {
	return p.PrivateKeyPEM
}
