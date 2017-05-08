package secrets

// Secrets is an interface implementing Secrets
type Secrets interface {
	Type() PrivateSecretsType
	EncodingKey() interface{}
	PublicKey() interface{}
	DecodingKey(server string, ackCert, prevCert interface{}) (interface{}, error)
	TransmittedKey() []byte
	VerifyPublicKey(pkey []byte) (interface{}, error)
	AckSize() uint32
}

// PrivateSecretsType identifies the different secrets that are supported
type PrivateSecretsType int

const (
	// PKIType  for asymmetric signing
	PKIType PrivateSecretsType = iota
	// PSKType  for symetric signing
	PSKType
	// PKICompactType is for asymetric signing using compact JWTs on the wire
	PKICompactType
	// PKINull is for debugging
	PKINull
)
