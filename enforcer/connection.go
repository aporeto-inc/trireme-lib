package enforcer

import (
	"fmt"
	"sync"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/aporeto-inc/trireme/crypto"
)

var (
	// TraceLogging provides very high level of detail logs for connections
	TraceLogging int
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
	mutex sync.Mutex
	state TCPFlowState
	Auth  AuthInfo

	// Debugging Information
	flowReported bool
	logs         []string
}

// TCPConnectionExpirationNotifier handles processing the expiration of an element
func TCPConnectionExpirationNotifier(c cache.DataStore, id interface{}, item interface{}) {

	if conn, ok := item.(*TCPConnection); ok {
		conn.Cleanup(true)
	}
}

// String returns a printable version of connection
func (c *TCPConnection) String() string {

	return fmt.Sprintf("state:%d auth: %+v", c.state, c.Auth)
}

// GetState is used to return the state
func (c *TCPConnection) GetState() TCPFlowState {

	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.state
}

// SetState is used to setup the state for the TCP connection
func (c *TCPConnection) SetState(state TCPFlowState) {

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.state = state

	if TraceLogging == 0 {
		return
	}

	c.logs = append(c.logs, fmt.Sprintf("set-state: %s %d", c.String(), state))
}

// SetReported is used to track if a flow is reported
func (c *TCPConnection) SetReported(dropped bool) {

	c.mutex.Lock()
	defer c.mutex.Unlock()

	repeatedReporting := false
	if !c.flowReported {
		c.flowReported = true
	} else {
		repeatedReporting = true
	}

	if TraceLogging == 0 {
		return
	}

	// Logging information
	reported := "flow-reported:"
	if repeatedReporting {
		reported = reported + " (ERROR duplicate reporting)"
	}
	if dropped {
		reported = reported + " dropped: "
	} else {
		reported = reported + " accepted: "
	}
	reported = reported + c.String()

	c.logs = append(c.logs, reported)
}

// SetPacketInfo is used to setup the state for the TCP connection
func (c *TCPConnection) SetPacketInfo(flowHash, tcpFlags string) {

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if TraceLogging == 0 {
		return
	}

	pktLog := fmt.Sprintf("pkt-registered: [%s] tcpf:%s %s", flowHash, tcpFlags, c.String())
	c.logs = append(c.logs, pktLog)
}

// Cleanup will provide information when a connection is removed by a timer.
func (c *TCPConnection) Cleanup(expiration bool) {

	c.mutex.Lock()
	defer c.mutex.Unlock()

	logStr := ""
	for i, v := range c.logs {
		logStr = logStr + fmt.Sprintf("[%05d]: %s\n", i, v)
	}
	// Logging information
	if !c.flowReported {
		zap.L().Error("Connection not reported",
			zap.String("connection", c.String()),
			zap.String("logs", logStr))
	} else {
		zap.L().Debug("Connection reported",
			zap.String("connection", c.String()),
			zap.String("logs", logStr))
	}
}

// NewTCPConnection returns a TCPConnection information struct
func NewTCPConnection(trackFlowReporting bool) *TCPConnection {

	c := &TCPConnection{
		state:        TCPSynSend,
		mutex:        sync.Mutex{},
		flowReported: trackFlowReporting,
		logs:         make([]string, 0),
	}
	initConnection(&c.Auth)
	return c
}

// initConnection creates the state information for a new connection
func initConnection(s *AuthInfo) {

	nonse, _ := crypto.GenerateRandomBytes(32)
	s.LocalContext = nonse
}
