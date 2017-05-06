package secrets

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	"github.com/aporeto-inc/trireme/crypto"
	"github.com/aporeto-inc/trireme/enforcer/utils/pkiverifier"
	"go.uber.org/zap"
)

// CompactPKI holds all PKI information
type CompactPKI struct {
	PrivateKeyPEM []byte
	PublicKeyPEM  []byte
	AuthorityPEM  []byte
	privateKey    *ecdsa.PrivateKey
	publicKey     *x509.Certificate
	certPool      *x509.CertPool
	txKey         []byte
	verifier      *pkiverifier.PKIConfiguration
}

// NewCompactPKI creates new secrets for PKI implementation based on compact encoding
func NewCompactPKI(keyPEM, certPEM, caPEM, txKey []byte) (*CompactPKI, error) {

	zap.L().Debug("Initializing with Compact PKI")

	key, cert, caCertPool, err := crypto.LoadAndVerifyECSecrets(keyPEM, certPEM, caPEM)
	if err != nil {
		return nil, err
	}

	caKey, err := crypto.LoadCertificate(caPEM)
	if err != nil {
		return nil, err
	}

	if len(txKey) == 0 {
		return nil, fmt.Errorf("TransmitToken missing")
	}

	p := &CompactPKI{
		PrivateKeyPEM: keyPEM,
		PublicKeyPEM:  certPEM,
		AuthorityPEM:  caPEM,
		privateKey:    key,
		publicKey:     cert,
		certPool:      caCertPool,
		txKey:         txKey,
		verifier:      pkiverifier.NewConfig(caKey.PublicKey.(*ecdsa.PublicKey), nil, -1),
	}

	return p, nil
}

// Type implements the interface Secrets
func (p *CompactPKI) Type() PrivateSecretsType {
	return PKICompactType
}

// EncodingKey returns the private key
func (p *CompactPKI) EncodingKey() interface{} {
	return p.privateKey
}

// PublicKey returns the public key
func (p *CompactPKI) PublicKey() interface{} {
	return p.publicKey
}

// DecodingKey returns the public key
func (p *CompactPKI) DecodingKey(server string, ackKey interface{}, prevKey interface{}) (interface{}, error) {

	// If we have an inband certificate, return this one
	if ackKey != nil {
		return ackKey.(*ecdsa.PublicKey), nil
	}

	// Otherwise, return the prevCert
	if prevKey != nil {
		return prevKey, nil
	}

	return nil, fmt.Errorf("No valid certificate")
}

// VerifyPublicKey verifies if the inband public key is correct.
func (p *CompactPKI) VerifyPublicKey(pkey []byte) (interface{}, error) {

	return p.verifier.Verify(pkey)

}

// TransmittedKey returns the PEM of the public key in the case of PKI
// if there is no certificate cache configured
func (p *CompactPKI) TransmittedKey() []byte {
	return p.txKey
}

// AckSize returns the default size of an ACK packet
func (p *CompactPKI) AckSize() uint32 {
	return uint32(322)
}

// AuthPEM returns the Certificate Authority PEM
func (p *CompactPKI) AuthPEM() []byte {
	return p.AuthorityPEM
}

// TransmittedPEM returns the PEM certificate that is transmitted
func (p *CompactPKI) TransmittedPEM() []byte {
	return p.PublicKeyPEM
}

// EncodingPEM returns the certificate PEM that is used for encoding
func (p *CompactPKI) EncodingPEM() []byte {
	return p.PrivateKeyPEM
}
