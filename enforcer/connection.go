package enforcer

import (
	"fmt"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/crypto"
)

// AuthInfo keeps authentication information about a connection
type AuthInfo struct {
	LocalContext    []byte
	RemoteContext   []byte
	RemoteContextID string
	RemotePublicKey interface{}
	RemoteIP        string
	RemotePort      string
}

// TCPConnection is information regarding TCP Connection
type TCPConnection struct {
	state TCPFlowState
	Auth  AuthInfo

	// Debugging Information
	mutex        sync.Mutex
	flowReported bool
	logs         []string
}

// TCPConnectionExpirationNotifier handles processing the expiration of an element
func TCPConnectionExpirationNotifier(c cache.DataStore, id interface{}, item interface{}) {

	if conn, ok := item.(*TCPConnection); ok {
		conn.Cleanup(true)
	}
}

// GetState is used to return the state
func (c *TCPConnection) GetState() TCPFlowState {
	return c.state
}

// SetState is used to setup the state for the TCP connection
func (c *TCPConnection) SetState(state TCPFlowState) {

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.state = state

	if log.GetLevel() < log.DebugLevel {
		return
	}

	// Logging information
	authStr := fmt.Sprintf("%+v", c.Auth)
	stateChange := fmt.Sprintf("set-state: %d -> %d (%s)", c.state, state, authStr)
	c.logs = append(c.logs, stateChange)
}

// SetReported is used to track if a flow is reported
func (c *TCPConnection) SetReported(dropped bool) {

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Logging information
	reported := "flow-reported:"
	if dropped {
		reported = reported + " dropped: "
	} else {
		reported = reported + " accepted: "
	}
	if c.flowReported {
		reported = reported + " Again ! (Error)"
	} else {
		c.flowReported = true
	}

	if log.GetLevel() < log.DebugLevel {
		return
	}

	authStr := fmt.Sprintf(" (%+v)", c.Auth)
	reported = reported + authStr

	c.logs = append(c.logs, reported)
}

// SetPacketInfo is used to setup the state for the TCP connection
func (c *TCPConnection) SetPacketInfo(flowHash, tcpFlags string) {

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if log.GetLevel() < log.DebugLevel {
		return
	}

	// Logging information
	authStr := fmt.Sprintf("%+v", c.Auth)
	pktLog := fmt.Sprintf("pkt-registered: [%s] tcpf:%s state:%d (%s)", flowHash, tcpFlags, c.state, authStr)
	c.logs = append(c.logs, pktLog)
}

// Cleanup will provide information when a connection is removed by a timer.
func (c *TCPConnection) Cleanup(expiration bool) {

	c.mutex.Lock()
	defer c.mutex.Unlock()

	authStr := fmt.Sprintf("%+v", c.Auth)
	logStr := ""
	for i, v := range c.logs {
		logStr = logStr + fmt.Sprintf("[%05d]: %s\n", i, v)
	}
	// Logging information
	if !c.flowReported {

		log.WithFields(log.Fields{
			"package":         "enforcer",
			"expiring":        expiration,
			"connectionState": c.state,
			"authInfo":        authStr,
			"logs":            logStr,
		}).Error("Connection not reported")
	} else {

		log.WithFields(log.Fields{
			"package":         "enforcer",
			"expiring":        expiration,
			"connectionState": c.state,
			"authInfo":        authStr,
			"logs":            logStr,
		}).Debug("Connection reported")
	}
}

// NewTCPConnection returns a TCPConnection information struct
func NewTCPConnection() *TCPConnection {

	c := &TCPConnection{
		state: TCPSynSend,
		mutex: sync.Mutex{},
		logs:  make([]string, 0),
	}
	initConnection(&c.Auth)
	return c
}

// initConnection creates the state information for a new connection
func initConnection(s *AuthInfo) {

	nonse, _ := crypto.GenerateRandomBytes(32)
	s.LocalContext = nonse
}
