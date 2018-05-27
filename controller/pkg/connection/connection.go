package connection

import (
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/controller/pkg/pucontext"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/utils/cache"
	"github.com/aporeto-inc/trireme-lib/utils/crypto"
)

// TCPFlowState identifies the constants of the state of a TCP connectioncon
type TCPFlowState int

// ProxyConnState identifies the constants of the state of a proxied connection
type ProxyConnState int

const (

	// TCPSynSend is the state where the Syn packets has been send, but no response has been received
	TCPSynSend TCPFlowState = iota

	// TCPSynReceived indicates that the syn packet has been received
	TCPSynReceived

	// TCPSynAckSend indicates that the SynAck packet has been send
	TCPSynAckSend

	// TCPSynAckReceived is the state where the SynAck has been received
	TCPSynAckReceived

	// TCPAckSend indicates that the ack packets has been sent
	TCPAckSend

	// TCPAckProcessed is the state that the negotiation has been completed
	TCPAckProcessed

	// TCPData indicates that the packets are now data packets
	TCPData

	// UnknownState indicates that this an existing connection in the uknown state.
	UnknownState
)

const (
	// ClientTokenSend Init token send for client
	ClientTokenSend ProxyConnState = iota

	// ServerReceivePeerToken -- waiting to receive peer token
	ServerReceivePeerToken

	// ServerSendToken -- Send our own token and the client tokens
	ServerSendToken

	// ClientPeerTokenReceive -- Receive signed tokens from server
	ClientPeerTokenReceive

	// ClientSendSignedPair -- Sign the (token/nonce pair) and send
	ClientSendSignedPair

	// ServerAuthenticatePair -- Authenticate pair of tokens
	ServerAuthenticatePair
)
const (

	// RejectReported represents that flow was reported as rejected
	RejectReported bool = true

	// AcceptReported represents that flow was reported as accepted
	AcceptReported bool = false
)

// AuthInfo keeps authentication information about a connection
type AuthInfo struct {
	LocalContext         []byte
	RemoteContext        []byte
	RemoteContextID      string
	RemotePublicKey      interface{}
	RemoteIP             string
	RemotePort           string
	LocalServiceContext  []byte
	RemoteServiceContext []byte
}

// TCPConnection is information regarding TCP Connection
type TCPConnection struct {
	sync.RWMutex

	state TCPFlowState
	Auth  AuthInfo

	// Debugging Information
	flowReported int

	// ServiceData allows services to associate state with a connection
	ServiceData interface{}

	// Context is the pucontext.PUContext that is associated with this connection
	// Minimizes the number of caches and lookups
	Context *pucontext.PUContext

	// TimeOut signals the timeout to be used by the state machines
	TimeOut time.Duration

	// Debugging information - pushed to the end for compact structure
	flowLastReporting bool

	// ServiceConnection indicates that this connection is handled by a service
	ServiceConnection bool

	// ReportFlowPolicy holds the last matched observed policy
	ReportFlowPolicy *policy.FlowPolicy

	// PacketFlowPolicy holds the last matched actual policy
	PacketFlowPolicy *policy.FlowPolicy
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
}

// SetReported is used to track if a flow is reported
func (c *TCPConnection) SetReported(flowState bool) {

	c.flowReported++

	if c.flowReported > 1 && c.flowLastReporting != flowState {
		zap.L().Info("Connection reported multiple times",
			zap.Int("report count", c.flowReported),
			zap.Bool("previous", c.flowLastReporting),
			zap.Bool("next", flowState),
		)
	}

	c.flowLastReporting = flowState
}

// Cleanup will provide information when a connection is removed by a timer.
func (c *TCPConnection) Cleanup(expiration bool) {
	// Logging information
	if c.flowReported == 0 {
		zap.L().Error("Connection not reported",
			zap.String("connection", c.String()))
	}
}

// NewTCPConnection returns a TCPConnection information struct
func NewTCPConnection(context *pucontext.PUContext) *TCPConnection {

	nonce, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		return nil
	}
	return &TCPConnection{
		state:   TCPSynSend,
		Context: context,
		Auth: AuthInfo{
			LocalContext: nonce,
		},
	}
}

// ProxyConnection is a record to keep state of proxy auth
type ProxyConnection struct {
	sync.Mutex

	state            ProxyConnState
	Auth             AuthInfo
	ReportFlowPolicy *policy.FlowPolicy
	PacketFlowPolicy *policy.FlowPolicy
	reported         bool
}

// NewProxyConnection returns a new Proxy Connection
func NewProxyConnection() *ProxyConnection {

	return &ProxyConnection{
		state: ClientTokenSend,
	}
}

// GetState returns the state of a proxy connection
func (c *ProxyConnection) GetState() ProxyConnState {

	return c.state
}

// SetState is used to setup the state for the Proxy Connection
func (c *ProxyConnection) SetState(state ProxyConnState) {

	c.state = state
}

// SetReported sets the flag to reported when the conn is reported
func (c *ProxyConnection) SetReported(reported bool) {
	c.reported = reported
}
