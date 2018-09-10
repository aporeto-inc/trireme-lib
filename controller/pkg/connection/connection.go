package connection

import (
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
	"go.aporeto.io/trireme-lib/utils/crypto"
)

// TCPFlowState identifies the constants of the state of a TCP connectioncon
type TCPFlowState int

// UDPFlowState identifies the constants of the state of a UDP connection.
type UDPFlowState int

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
	// UDPStart is the state where a syn will be sent.
	UDPStart UDPFlowState = iota

	// UDPClientSendSyn is the state where a syn has been sent.
	UDPClientSendSyn

	// UDPClientSendAck  is the state where application side has send the ACK.
	UDPClientSendAck

	// UDPReceiverSendSynAck is the state where syn ack packet has been sent.
	UDPReceiverSendSynAck

	// UDPReceiverProcessedAck is the state that the negotiation has been completed.
	UDPReceiverProcessedAck

	// UDPData is the state where data is being transmitted.
	UDPData
)

// MaximumUDPQueueLen is the maximum number of UDP packets buffered.
const MaximumUDPQueueLen = 50

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
	nonce, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		return nil
	}

	return &ProxyConnection{
		state: ClientTokenSend,
		Auth: AuthInfo{
			LocalContext: nonce,
		},
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

// UDPConnection is information regarding UDP connection.
type UDPConnection struct {
	sync.RWMutex

	state   UDPFlowState
	Context *pucontext.PUContext
	Auth    AuthInfo
	// Debugging Information
	flowReported int

	ReportFlowPolicy *policy.FlowPolicy
	PacketFlowPolicy *policy.FlowPolicy
	// ServiceData allows services to associate state with a connection
	ServiceData interface{}

	// PacketQueue indicates app UDP packets queued while authorization is in progress.
	PacketQueue chan *packet.Packet
	Writer      afinetrawsocket.SocketWriter
	// Debugging information - pushed to the end for compact structure
	flowLastReporting bool
	reported          bool
	// ServiceConnection indicates that this connection is handled by a service
	ServiceConnection bool

	// Stop channels for restransmissions
	synStop    chan bool
	synAckStop chan bool
	ackStop    chan bool

	TestIgnore bool
}

// NewUDPConnection returns UDPConnection struct.
func NewUDPConnection(context *pucontext.PUContext, writer afinetrawsocket.SocketWriter) *UDPConnection {

	nonce, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		return nil
	}

	return &UDPConnection{
		state:       UDPStart,
		Context:     context,
		PacketQueue: make(chan *packet.Packet, MaximumUDPQueueLen),
		Writer:      writer,
		Auth: AuthInfo{
			LocalContext: nonce,
		},
		synStop:    make(chan bool),
		synAckStop: make(chan bool),
		ackStop:    make(chan bool),
		TestIgnore: true,
	}
}

// SynStop issues a stop on the synStop channel.
func (c *UDPConnection) SynStop() {
	select {
	case c.synStop <- true:
	default:
		zap.L().Debug("Packet loss - channel was already done")
	}

}

// SynAckStop issues a stop in the synAckStop channel.
func (c *UDPConnection) SynAckStop() {
	select {
	case c.synAckStop <- true:
	default:
		zap.L().Debug("Packet loss - channel was already done")
	}
}

// AckStop issues a stop in the Ack channel.
func (c *UDPConnection) AckStop() {
	select {
	case c.ackStop <- true:
	default:
		zap.L().Debug("Packet loss - channel was already done")
	}

}

// SynChannel returns the SynStop channel.
func (c *UDPConnection) SynChannel() chan bool {
	return c.synStop
}

// SynAckChannel returns the SynAck stop channel.
func (c *UDPConnection) SynAckChannel() chan bool {
	return c.synAckStop
}

// AckChannel returns the Ack stop channel.
func (c *UDPConnection) AckChannel() chan bool {
	return c.ackStop
}

// GetState is used to get state of UDP Connection.
func (c *UDPConnection) GetState() UDPFlowState {
	return c.state
}

// SetState is used to setup the state for the UDP Connection.
func (c *UDPConnection) SetState(state UDPFlowState) {
	c.state = state
}

// QueuePackets queues UDP packets till the flow is authenticated.
func (c *UDPConnection) QueuePackets(udpPacket *packet.Packet) (err error) {

	buffer := make([]byte, len(udpPacket.Buffer))
	copy(buffer, udpPacket.Buffer)

	copyPacket, err := packet.New(packet.PacketTypeApplication, buffer, udpPacket.Mark, true)
	if err != nil {
		return fmt.Errorf("Unable to copy packets to queue:%s", err)
	}

	select {
	case c.PacketQueue <- copyPacket:
	default:
		return fmt.Errorf("Queue is full")
	}

	return nil
}

// DropPackets drops packets on errors during Authorization.
func (c *UDPConnection) DropPackets() {
	close(c.PacketQueue)
	c.PacketQueue = make(chan *packet.Packet, MaximumUDPQueueLen)
}

// ReadPacket reads a packet from the queue.
func (c *UDPConnection) ReadPacket() *packet.Packet {
	select {
	case p := <-c.PacketQueue:
		return p
	default:
		return nil
	}
}

// SetReported is used to track if a flow is reported
func (c *UDPConnection) SetReported(flowState bool) {

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
