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
	return uint32(279)
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
