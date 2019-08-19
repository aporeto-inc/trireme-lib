package secrets

// PSKSecrets holds the shared key.
type PSKSecrets struct {
	SharedKey []byte
}

// NewPSKSecrets creates new PSK Secrets.
func NewPSKSecrets(psk []byte) *PSKSecrets {
	return &PSKSecrets{SharedKey: psk}
}

// Type implements the Secrets interface.
func (p *PSKSecrets) Type() PrivateSecretsType {
	return PSKType
}

// EncodingKey returns the pre-shared key.
func (p *PSKSecrets) EncodingKey() interface{} {
	return p.SharedKey
}

// PublicKey returns the public key
func (p *PSKSecrets) PublicKey() interface{} {
	return p.SharedKey
}

// DecodingKey returns the preshared key.
func (p *PSKSecrets) DecodingKey(server string, ackCert, prevCert interface{}) (interface{}, error) {
	return p.SharedKey, nil
}

// TransmittedKey returns nil in the case of pre-shared key.
func (p *PSKSecrets) TransmittedKey() []byte {
	return nil
}

// VerifyPublicKey always returns nil for pre-shared secrets.
func (p *PSKSecrets) VerifyPublicKey(pkey []byte) (interface{}, error) {
	return nil, nil
}

// AckSize returns the expected size of ack packets.
func (p *PSKSecrets) AckSize() uint32 {
	return uint32(237)
}

// AuthPEM returns the Certificate Authority PEM.
func (p *PSKSecrets) AuthPEM() []byte {
	return p.SharedKey
}

// TransmittedPEM returns the PEM certificate that is transmitted.
func (p *PSKSecrets) TransmittedPEM() []byte {
	return p.SharedKey
}

// EncodingPEM returns the certificate PEM that is used for encoding.
func (p *PSKSecrets) EncodingPEM() []byte {
	return p.SharedKey
}

// PublicSecrets returns the secrets that are marshallable over the RPC interface.
func (p *PSKSecrets) PublicSecrets() PublicSecrets {
	return &PSKPublicSecrets{
		Type:      PSKType,
		SharedKey: p.SharedKey,
	}
}

// PSKPublicSecrets includes all the secrets that can be transmitted over
// the RPC interface.
type PSKPublicSecrets struct {
	Type      PrivateSecretsType
	SharedKey []byte
}

// SecretsType returns the type of secrets.
func (p *PSKPublicSecrets) SecretsType() PrivateSecretsType {
	return p.Type
}

// CertAuthority returns the cert authority - N/A to PSK
func (p *PSKPublicSecrets) CertAuthority() []byte {
	return []byte{}
}
