package enforcer

import "github.com/aporeto-inc/trireme/crypto"

// Connection keeps information about a connection
type Connection struct {
	State           FlowState
	LocalContext    []byte
	RemoteContext   []byte
	LocalContextID  string
	RemoteContextID string
	RemotePublicKey interface{}
}

// NewConnection creates the state information for a new connection
func NewConnection() *Connection {

	var err error

	c := &Connection{
		State:           SynSend,
		RemotePublicKey: nil,
	}

	nonse, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		return nil
	}

	c.LocalContext = nonse
	c.RemoteContext = nil

	return c
}
