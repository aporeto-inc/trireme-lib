package secrets

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"time"

	"go.aporeto.io/trireme-lib/v11/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/pkiverifier"
	"go.aporeto.io/trireme-lib/v11/utils/crypto"
	"go.uber.org/zap"
)

const (
	compactPKIAckSize = 300
)

// CompactPKI holds all PKI information
type CompactPKI struct {
	PrivateKeyPEM []byte
	PublicKeyPEM  []byte
	AuthorityPEM  []byte
	TokenKeyPEMs  [][]byte
	Compressed    claimsheader.CompressionType
	privateKey    *ecdsa.PrivateKey
	publicKey     *x509.Certificate
	txKey         []byte
	verifier      pkiverifier.PKITokenVerifier
}

// NewCompactPKI creates new secrets for PKI implementation based on compact encoding
func NewCompactPKI(keyPEM []byte, certPEM []byte, caPEM []byte, txKey []byte, compress claimsheader.CompressionType) (*CompactPKI, error) {

	zap.L().Warn("DEPRECATED. secrets.NewCompactPKI is deprecated in favor of secrets.NewCompactPKIWithTokenCA")
	return NewCompactPKIWithTokenCA(keyPEM, certPEM, caPEM, [][]byte{caPEM}, txKey, compress)
}

// NewCompactPKIWithTokenCA creates new secrets for PKI implementation based on compact encoding.
//    keyPEM: is the private key that will be used for signing tokens formated as a PEM file.
//    certPEM: is the public key that will be used formated as a PEM file.
//    tokenKeyPEMs: is a list of public keys that can be used to verify the public token that
//                  that is transmitted over the wire. These are essentially the public CA PEMs
//                  that were used to sign the txtKey
//    txKey: is the public key that is send over the wire.
//    compressionType: is packed with the secrets to indicate compression.
func NewCompactPKIWithTokenCA(keyPEM []byte, certPEM []byte, caPEM []byte, tokenKeyPEMs [][]byte, txKey []byte, compress claimsheader.CompressionType) (*CompactPKI, error) {

	key, cert, _, err := crypto.LoadAndVerifyECSecrets(keyPEM, certPEM, caPEM)
	if err != nil {
		return nil, err
	}

	tokenKeys := make([]*ecdsa.PublicKey, len(tokenKeyPEMs))
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
		Compressed:    compress,
		privateKey:    key,
		publicKey:     cert,
		txKey:         txKey,
		verifier:      pkiverifier.NewPKIVerifier(tokenKeys, 5*time.Minute),
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

//KeyAndClaims returns both the key and any attributes associated with the public key.
func (p *CompactPKI) KeyAndClaims(pkey []byte) (interface{}, []string, time.Time, error) {
	kc, err := p.verifier.Verify(pkey)
	if err != nil {
		return nil, nil, time.Unix(0, 0), err
	}
	return kc.PublicKey, kc.Tags, kc.Expiration, nil
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

// PublicSecrets returns the secrets that are marshallable over the RPC interface.
func (p *CompactPKI) PublicSecrets() PublicSecrets {
	return &CompactPKIPublicSecrets{
		Type:        PKICompactType,
		Key:         p.PrivateKeyPEM,
		Certificate: p.PublicKeyPEM,
		CA:          p.AuthorityPEM,
		Token:       p.txKey,
		TokenCAs:    p.TokenKeyPEMs,
		Compressed:  p.Compressed,
	}
}

// CompactPKIPublicSecrets includes all the secrets that can be transmitted over
// the RPC interface.
type CompactPKIPublicSecrets struct {
	Type        PrivateSecretsType
	Key         []byte
	Certificate []byte
	CA          []byte
	TokenCAs    [][]byte
	Token       []byte
	Compressed  claimsheader.CompressionType
}

// SecretsType returns the type of secrets.
func (p *CompactPKIPublicSecrets) SecretsType() PrivateSecretsType {
	return p.Type
}

// CertAuthority returns the cert authority
func (p *CompactPKIPublicSecrets) CertAuthority() []byte {
	return p.CA
}
