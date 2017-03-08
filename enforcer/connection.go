package enforcer

import "github.com/aporeto-inc/trireme/crypto"

// AuthInfo keeps authentication information about a connection
type AuthInfo struct {
	LocalContext    []byte
	RemoteContext   []byte
	LocalContextID  string
	RemoteContextID string
	RemotePublicKey interface{}
	RemoteIP        string
	RemotePort      string
}

// TCPConnection is information regarding TCP Connection
type TCPConnection struct {
	State TCPFlowState
	Auth  AuthInfo
}

// NewTCPConnection returns a TCPConnection information struct
func NewTCPConnection() *TCPConnection {

	c := &TCPConnection{
		State: TCPSynSend,
	}
	initConnection(&c.Auth)
	return c
}

// initConnection creates the state information for a new connection
func initConnection(s *AuthInfo) {

	nonse, _ := crypto.GenerateRandomBytes(32)
	s.LocalContext = nonse
}
