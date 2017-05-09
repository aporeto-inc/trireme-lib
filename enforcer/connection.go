package enforcer

import (
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/cache"
)

var (
	// TraceLogging provides very high level of detail logs for connections
	TraceLogging int
)

// TCPFlowState identifies the constants of the state of a TCP connectioncon
type TCPFlowState int

const (

	// TCPSynSend is the state where the Syn packets has been send, but no response has been received
	TCPSynSend TCPFlowState = iota

	// TCPSynReceived indicates that the syn packet has been received
	TCPSynReceived

	// TCPSynAckSend indicates that the SynAck packet has been send
	TCPSynAckSend

	// TCPSynAckReceived is the state where the SynAck has been received
	TCPSynAckReceived

	// TCPAckSend indicates that the ack packets has been send
	TCPAckSend

	// TCPAckProcessed is the state that the negotiation has been completed
	TCPAckProcessed

	// TCPData indicates that the packets are now data packets
	TCPData
)

const (

	// RejectReported represents that flow was reported as rejected
	RejectReported bool = true

	// AcceptReported represents that flow was reported as accepted
	AcceptReported bool = false
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
	sync.Mutex

	state TCPFlowState
	Auth  AuthInfo

	// Debugging Information
	flowReported int
	logs         []string

	// ServiceData allows services to associate state with a connection
	ServiceData interface{}

	// Context is the PUContext that is associated with this connection
	// Minimizes the number of caches and lookups
	Context *PUContext

	// TimeOut signals the timeout to be used by the state machines
	TimeOut time.Duration

	// Debugging information - pushed to the end for compact structure
	flowLastReporting bool

	// ServiceConnection indicates that this connection is handled by a service
	ServiceConnection bool
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

	return c.state
}

// SetState is used to setup the state for the TCP connection
func (c *TCPConnection) SetState(state TCPFlowState) {

	c.state = state

	if TraceLogging == 0 {
		return
	}

	c.logs = append(c.logs, fmt.Sprintf("set-state: %s %d", c.String(), state))
}

// SetReported is used to track if a flow is reported
func (c *TCPConnection) SetReported(flowState bool) {

	c.flowReported++

	state := ""
	if c.flowReported > 1 {
		state = fmt.Sprintf("%t %t", c.flowLastReporting, flowState)
		zap.L().Debug("Connection reported multiple times",
			zap.String("state", state))
	}

	c.flowLastReporting = flowState

	if TraceLogging == 0 {
		return
	}

	// Logging information
	reported := "flow-reported:"
	if c.flowReported > 1 {
		reported = reported + " (ERROR duplicate reporting) " + state
	}

	if flowState {
		reported = reported + " dropped: "
	} else {
		reported = reported + " accepted: "
	}
	reported = reported + c.String()

	c.logs = append(c.logs, reported)
}

// SetPacketInfo is used to setup the state for the TCP connection
func (c *TCPConnection) SetPacketInfo(flowHash, tcpFlags string) {

	if TraceLogging == 0 {
		return
	}

	pktLog := fmt.Sprintf("pkt-registered: [%s] tcpf:%s %s", flowHash, tcpFlags, c.String())
	c.logs = append(c.logs, pktLog)
}

// Cleanup will provide information when a connection is removed by a timer.
func (c *TCPConnection) Cleanup(expiration bool) {

	logStr := ""
	for i, v := range c.logs {
		logStr = logStr + fmt.Sprintf("[%05d]: %s\n", i, v)
	}
	// Logging information
	if c.flowReported == 0 && len(c.logs) > 1 {
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
func NewTCPConnection() *TCPConnection {

	c := &TCPConnection{
		state: TCPSynSend,
		logs:  []string{"Initialized"},
	}

	return c
}
