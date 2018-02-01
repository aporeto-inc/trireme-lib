package secrets

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"

	"github.com/aporeto-inc/trireme-lib/controller/enforcer/utils/pkiverifier"
	"github.com/aporeto-inc/trireme-lib/utils/crypto"
	"go.uber.org/zap"
)

// CompactPKI holds all PKI information
type CompactPKI struct {
	PrivateKeyPEM []byte
	PublicKeyPEM  []byte
	AuthorityPEM  []byte
	TokenKeyPEMs  [][]byte
	privateKey    *ecdsa.PrivateKey
	publicKey     *x509.Certificate
	certPool      *x509.CertPool
	txKey         []byte
	verifier      pkiverifier.PKITokenVerifier
}

// NewCompactPKI creates new secrets for PKI implementation based on compact encoding
func NewCompactPKI(keyPEM []byte, certPEM []byte, caPEM []byte, txKey []byte) (*CompactPKI, error) {

	zap.L().Warn("DEPRECATED. secrets.NewCompactPKI is deprecated in favor of secrets.NewCompactPKIWithTokenCA")
	return NewCompactPKIWithTokenCA(keyPEM, certPEM, caPEM, [][]byte{[]byte(caPEM)}, txKey)
}

// NewCompactPKIWithTokenCA creates new secrets for PKI implementation based on compact encoding
func NewCompactPKIWithTokenCA(keyPEM []byte, certPEM []byte, caPEM []byte, tokenKeyPEMs [][]byte, txKey []byte) (*CompactPKI, error) {

	zap.L().Debug("Initializing with Compact PKI")

	key, cert, caCertPool, err := crypto.LoadAndVerifyECSecrets(keyPEM, certPEM, caPEM)
	if err != nil {
		return nil, err
	}

	var tokenKeys []*ecdsa.PublicKey
	for _, ca := range tokenKeyPEMs {

		caCert, err := crypto.LoadCertificate(ca)
		if err != nil {
			return nil, err
		}

		tokenKeys = append(tokenKeys, caCert.PublicKey.(*ecdsa.PublicKey))
	}

	if len(txKey) == 0 {
		return nil, errors.New("transmit token missing")
	}

	p := &CompactPKI{
		PrivateKeyPEM: keyPEM,
		PublicKeyPEM:  certPEM,
		AuthorityPEM:  caPEM,
		TokenKeyPEMs:  tokenKeyPEMs,
		privateKey:    key,
		publicKey:     cert,
		certPool:      caCertPool,
		txKey:         txKey,
		verifier:      pkiverifier.NewPKIVerifier(tokenKeys, -1),
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

	return nil, errors.New("invalid certificate")
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

// TokenPEMs returns the Token Certificate Authorities
func (p *CompactPKI) TokenPEMs() [][]byte {

	if len(p.TokenKeyPEMs) > 0 {
		return p.TokenKeyPEMs
	}

	return [][]byte{p.AuthPEM()}
}

// TransmittedPEM returns the PEM certificate that is transmitted
func (p *CompactPKI) TransmittedPEM() []byte {
	return p.PublicKeyPEM
}

// EncodingPEM returns the certificate PEM that is used for encoding
func (p *CompactPKI) EncodingPEM() []byte {
	return p.PrivateKeyPEM
}
