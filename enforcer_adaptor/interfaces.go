//This is the interface we need to implement for trireme to call the enforcer.
//Any package that implements this interface can act as an enforcer
//We plan to use UNIX_SOCKET:RPC to communicate with the actual enforcer which is a separate process
package enforcer_adaptor

import "github.com/aporeto-inc/trireme/policy"

const MsgPipe = "/var/run/$contextid.sock"
const Enforcer_bin = "/opt/trireme/enforcer"

type PolicyEnforcer interface {
	// Enforce starts enforcing policies for the given policy.PUInfo.
	Enforce(contextID string, puInfo *policy.PUInfo) error

	// Unenforce stops enforcing policy for the given IP.
	Unenforce(contextID string) error

	// GetFilterQueue returns the current FilterQueueConfig.
	GetFilterQueue() *FilterQueue

	// Start starts the PolicyEnforcer.
	Start() error

	// Stop stops the PolicyEnforcer.
	Stop() error
}

type PublicKeyAdder interface {

	// PublicKeyAdd adds the given cert for the given host.
	PublicKeyAdd(host string, cert []byte) error
}
type Enforcer_request struct {
	seqnum        int
	method        string
	targetContext string
	request       interface{}
}

type Enforcer_response struct {
	seqnum   int
	method   string
	status   int
	response interface{}
}
type Enforcer_rpc_server interface {
	ProcessMessage(request_args *Enforcer_request, response *Enforcer_response) error
}

//This is consumed within the package enforcer we will declare it there
// type PacketProcessor interface {

// 	// PreProcessTCPAppPacket will be called for application packets and return value of false means drop packet.
// 	PreProcessTCPAppPacket(pkt interface{}) bool

// 	// PostProcessTCPAppPacket will be called for application packets and return value of false means drop packet.
// 	PostProcessTCPAppPacket(pkt interface{}, action interface{}) bool

// 	// PreProcessTCPNetPacket will be called for network packets and return value of false means drop packet
// 	PreProcessTCPNetPacket(pkt interface{}) bool

// 	// PostProcessTCPNetPacket will be called for network packets and return value of false means drop packet
// 	PostProcessTCPNetPacket(pkt interface{}, action interface{}) bool
// }
