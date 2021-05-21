package secrets

import (
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pkiverifier"
)

// LockedSecrets provides a way to use secrets where shared read access is required. The user becomes
// responsible for unlocking when done using them. The implementation should lock the access to secrets
// for reading, and pass down the function for unlocking.
type LockedSecrets interface {
	Secrets() (Secrets, func())
}

// Secrets is an interface implementing secrets
type Secrets interface {
	// EncodingKey returns the key used to encode the tokens.
	EncodingKey() interface{}
	// PublicKey returns the public ket of the secrets.
	PublicKey() interface{}
	// CertAuthority returns the CA
	CertAuthority() []byte
	// TransmittedKey returns the public key as a byte slice and as it is transmitted
	// on the wire.
	TransmittedKey() []byte
	// KeyAndClaims will verify the public key and return any claims that are part of the key.
	KeyAndClaims(pkey []byte) (interface{}, []string, time.Time, *pkiverifier.PKIControllerInfo, error)
	// AckSize calculates the size of the ACK packet based on the keys.
	AckSize() uint32
	// RPCSecrets returns the PEM formated secrets to be transmitted over the RPC interface.
	RPCSecrets() RPCSecrets
}

// ControllerInfo holds information about public keys
type ControllerInfo struct {
	// PublicKey is the public key for a controller which is used to verify the public token
	// that that is transmitted over the wire. These were used to sign the txtKey.
	PublicKey []byte
	// Controller is information for a given controller.
	Controller *pkiverifier.PKIControllerInfo
}

// RPCSecrets includes all the secrets that can be transmitted over
// the RPC interface.
type RPCSecrets struct {
	Key                []byte
	Certificate        []byte
	CA                 []byte
	TrustedControllers []*ControllerInfo
	Token              []byte
	Compressed         claimsheader.CompressionType
}
