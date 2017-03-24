package tokens

import "time"

// PSKSecrets holds the shared key
type PSKSecrets struct {
	SharedKey        []byte
	SecretExpiry     time.Duration
	format           TokenFormat
	sessionKeyExpiry time.Duration
	serverID         string
	jwtsigninghandle *JWTConfig
}

// NewPSKSecrets creates new PSK Secrets
func NewPSKSecrets(psk []byte, secretExpiry time.Duration, serverID string) *PSKSecrets {
	p := &PSKSecrets{
		SharedKey:        psk,
		format:           JWTTokens,
		SecretExpiry:     secretExpiry,
		sessionKeyExpiry: secretExpiry,
	}
	p.jwtsigninghandle, _ = NewJWT(p.SecretExpiry, p.serverID, p)
	return p
}

// Type implements the Secrets interface
func (p *PSKSecrets) Type() SecretsType {
	return PSKType
}

// EncodingKey returns the pre-shared key
func (p *PSKSecrets) EncodingKey() interface{} {
	return p.SharedKey
}

// DecodingKey returns the preshared key
func (p *PSKSecrets) DecodingKey(server string, ackCert, prevCert interface{}) (interface{}, error) {
	return p.SharedKey, nil
}

// TransmittedKey returns nil in the case of pre-shared key
func (p *PSKSecrets) TransmittedKey() []byte {
	return nil
}

// VerifyPublicKey always returns nil for pre-shared secrets
func (p *PSKSecrets) VerifyPublicKey(pkey []byte) (interface{}, error) {
	return nil, nil
}

// AckSize returns the expected size of ack packets
func (p *PSKSecrets) AckSize() uint32 {
	return uint32(335)
}

func (p *PSKSecrets) AuthPEM() []byte {
	return p.SharedKey
}

func (p *PSKSecrets) TransmittedPEM() []byte {
	return p.SharedKey
}

func (p *PSKSecrets) EncodingPEM() []byte {
	return p.SharedKey
}

func (p *PSKSecrets) CreateAndSign(outputFormat TokenFormat, attachCert bool, claims interface{}) []byte {
	if outputFormat == JWTTokens {
		signinghandle, _ := NewJWT(p.SecretExpiry, p.serverID, p)
		return signinghandle.CreateAndSign(attachCert, claims.(*ConnectionClaims))
	} else {
	}
	return []byte{}
}

func (p *PSKSecrets) Decode(inputFormat TokenFormat, decodeCert bool, buffer []byte, cert interface{}) (interface{}, interface{}) {
	if inputFormat == JWTTokens {
		return p.jwtsigninghandle.Decode(decodeCert, buffer, cert)
	} else {
	}
	return []byte{}, nil
}
