package compactpki

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pkiverifier"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/utils/crypto"
)

const (
	compactPKIAckSize = 300
)

// CompactPKI holds all PKI information
type CompactPKI struct {
	privateKeyPEM      []byte
	publicKeyPEM       []byte
	authorityPEM       []byte
	trustedControllers []*secrets.ControllerInfo
	compressed         claimsheader.CompressionType
	privateKey         *ecdsa.PrivateKey
	publicKey          *x509.Certificate
	txKey              []byte
	verifier           pkiverifier.PKITokenVerifier
}

// NewCompactPKIWithTokenCA creates new secrets for PKI implementation based on compact encoding.
//    keyPEM: is the private key that will be used for signing tokens formated as a PEM file.
//    certPEM: is the public key that will be used formated as a PEM file.
//    trustedControllers: is a list of trusted controllers.
//    txKey: is the public key that is send over the wire.
//    compressionType: is packed with the secrets to indicate compression.
func NewCompactPKIWithTokenCA(keyPEM []byte, certPEM []byte, caPEM []byte, trustedControllers []*secrets.ControllerInfo, txKey []byte, compress claimsheader.CompressionType) (*CompactPKI, error) {

	key, cert, _, err := crypto.LoadAndVerifyECSecrets(keyPEM, certPEM, caPEM)
	if err != nil {
		return nil, err
	}

	tokenKeys := make([]*pkiverifier.PKIPublicKey, len(trustedControllers))
	for _, tokenKey := range trustedControllers {
		caCert, err := crypto.LoadCertificate(tokenKey.PublicKey)
		if err != nil {
			return nil, err
		}

		namespaceKey := &pkiverifier.PKIPublicKey{
			PublicKey:  caCert.PublicKey.(*ecdsa.PublicKey),
			Controller: tokenKey.Controller,
		}

		tokenKeys = append(tokenKeys, namespaceKey)
	}

	if len(txKey) == 0 {
		return nil, errors.New("transmit token missing")
	}

	p := &CompactPKI{
		privateKeyPEM:      keyPEM,
		publicKeyPEM:       certPEM,
		authorityPEM:       caPEM,
		trustedControllers: trustedControllers,
		compressed:         compress,
		privateKey:         key,
		publicKey:          cert,
		txKey:              txKey,
		verifier:           pkiverifier.NewPKIVerifier(tokenKeys, 5*time.Minute),
	}

	return p, nil
}

// EncodingKey returns the private key
func (p *CompactPKI) EncodingKey() interface{} {
	return p.privateKey
}

// PublicKey returns the public key
func (p *CompactPKI) PublicKey() interface{} {
	return p.publicKey
}

// CertAuthority returns the cert authority
func (p *CompactPKI) CertAuthority() []byte {
	return p.authorityPEM
}

//KeyAndClaims returns both the key and any attributes associated with the public key.
func (p *CompactPKI) KeyAndClaims(pkey []byte) (interface{}, []string, time.Time, *pkiverifier.PKIControllerInfo, error) {
	kc, err := p.verifier.Verify(pkey)
	if err != nil {
		return nil, nil, time.Unix(0, 0), nil, err
	}
	return kc.PublicKey, kc.Tags, kc.Expiration, kc.Controller, nil
}

// TransmittedKey returns the PEM of the public key in the case of PKI
// if there is no certificate cache configured
func (p *CompactPKI) TransmittedKey() []byte {
	return p.txKey
}

// AckSize returns the default size of an ACK packet
func (p *CompactPKI) AckSize() uint32 {
	return uint32(compactPKIAckSize)
}

// RPCSecrets returns the secrets that are marshallable over the RPC interface.
func (p *CompactPKI) RPCSecrets() secrets.RPCSecrets {
	return secrets.RPCSecrets{
		Key:                p.privateKeyPEM,
		Certificate:        p.publicKeyPEM,
		CA:                 p.authorityPEM,
		Token:              p.txKey,
		TrustedControllers: p.trustedControllers,
		Compressed:         p.compressed,
	}
}
