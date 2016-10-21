package enforcer

import "github.com/aporeto-inc/trireme/policy"

// A PolicyEnforcer is implementing the enforcer that will modify//analyze the capture packets
type PolicyEnforcer interface {
	Enforce(contextID string, puInfo *policy.PUInfo) error
	Unenforce(ip string) error

	UpdatePU(ipaddress string, puInfo *policy.PUInfo) error

	Start() error
	Stop() error

	GetFilterQueue() *FilterQueueConfig
}

// PublicKeyAdder register a publicKey for a Node.
type PublicKeyAdder interface {
	PublicKeyAdd(host string, newCert []byte) error
}

// PacketProcessor is an interface implemented to stitch into our enforcer
type PacketProcessor interface {
	// PreProcessTCPAppPacket will be called for application packets and return value of false means drop packet.
	PreProcessTCPAppPacket(pkt interface{}) bool
	// PostProcessTCPAppPacket will be called for application packets and return value of false means drop packet.
	PostProcessTCPAppPacket(pkt interface{}, action interface{}) bool
	// PreProcessTCPNetPacket will be called for network packets and return value of false means drop packet
	PreProcessTCPNetPacket(pkt interface{}) bool
	// PostProcessTCPNetPacket will be called for network packets and return value of false means drop packet
	PostProcessTCPNetPacket(pkt interface{}, action interface{}) bool
}
