package tokens

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/x509"
	"strings"
	"time"

	"github.com/aporeto-inc/trireme/crypto"
	"github.com/aporeto-inc/trireme/policy"
)

// CustomTokenSignMethod describes the sign methods for the custome tokens
type CustomTokenSignMethod int

const (
	// PreSharedKey defines a pre-shared key implementation
	PreSharedKey CustomTokenSignMethod = iota
	// PKI defines a public/private key implementation
	PKI
)

const (
	lclIndex         = 64
	rmtIndex         = 96
	minBufferLength  = 128
	sizeOfRandom     = 32
	sizeOfMessageMac = 32
)

// CustomTokenConfig configures the custom token generator with the standard parameters
type CustomTokenConfig struct {

	// ValidityPeriod for the signed token
	ValidityPeriod time.Duration

	// Issuer is the server that signs the request
	Issuer string

	// SignMethod is the method to use for signing the labels
	SignMethod CustomTokenSignMethod

	// Key is an interface for either the Private Key or the Preshared Key
	Key interface{}
	// CA is the certificate of the CA that has signed the server keys
	CA *x509.Certificate
	// Cert is the certificate of the server
	Cert *x509.Certificate
	// CertPEM is a buffer of the PEM file that is send to other servers - Cached for efficiency
	CertPEM []byte
	// IncludeCert instructs the engine to transmit the certificate with each token
	IncludeCert bool
	// CertPool is pool of certificates that are already distributed out of band
	PublicKeyCache map[string]*ecdsa.PublicKey
}

// NewPSKCustomToken creates a new token generator for custom tokens
func NewPSKCustomToken(validity time.Duration, issuer string, psk []byte) *CustomTokenConfig {
	return &CustomTokenConfig{
		ValidityPeriod: validity,
		Issuer:         issuer,
		SignMethod:     PreSharedKey,
		Key:            psk,
	}
}

// CreateAndSign  creates a buffer for a new custom token and signs the token. Format
// is Signature, Random Local, Random Remote, Tags separated by the spaces
func (c *CustomTokenConfig) CreateAndSign(isAck bool, claims *ConnectionClaims) []byte {

	buffer := make([]byte, minBufferLength)

	// Copy the random part
	//  copy(buffer[lclIndex:lclIndex+sizeOfRandom], claims.LCL)
	copy(buffer[rmtIndex:rmtIndex+sizeOfRandom], claims.RMT)

	// If not an ACK packet copy the tags
	if !isAck {
		for k, v := range claims.T.Tags {
			tag := []byte(k + "=" + v + " ")
			buffer = append(buffer, tag...)
		}
	}

	// Sign the buffer
	signature, err := crypto.ComputeHmac256(buffer[lclIndex:], c.Key.([]byte))
	if err != nil {
		return []byte{}
	}

	// Add the signature as the first part of the buffer
	copy(buffer[0:], signature)

	// Return the buffer
	return buffer

}

// Decode decodes a string into the data structures for a custom token
func (c *CustomTokenConfig) Decode(isAck bool, data []byte, previousCert interface{}) (*ConnectionClaims, interface{}) {
	claims := &ConnectionClaims{}

	if len(data) < minBufferLength {
		return nil, nil
	}

	messageMac := data[:sizeOfMessageMac]
	expectedMac, err := crypto.ComputeHmac256(data[lclIndex:], c.Key.([]byte))
	if err != nil {
		return nil, nil
	}

	if !hmac.Equal(messageMac, expectedMac) {
		return nil, nil
	}

	// claims.LCL = data[lclIndex : lclIndex+sizeOfRandom]
	claims.RMT = data[rmtIndex : rmtIndex+sizeOfRandom]

	if !isAck {
		claims.T = policy.NewTagsMap(nil)
		buffer := bytes.NewBuffer(data[minBufferLength:])
		for {
			tag, err := buffer.ReadBytes([]byte(" ")[0])

			if err == nil {
				values := strings.Split(string(tag[:len(tag)-1]), "=")
				if len(values) != 2 {
					continue
				}

				claims.T.Add(values[0], values[1])
				continue
			}

			break
		}
	}

	return claims, nil
}
