package datapath

import "github.com/aporeto-inc/trireme/policy"

// A Datapath is implementing the DataPath that will modify//analyze the capture packets
type Datapath interface {
	AddPU(contextID string, puInfo *policy.PUInfo) error
	DeletePU(ip string) error
	UpdatePU(ipaddress string, puInfo *policy.PUInfo) error
	Start() error
	Stop() error

	GetFilterQueue() *FilterQueueConfig
}

// PublicKeyAdder register a publicKey for a Node.
type PublicKeyAdder interface {
	PublicKeyAdd(host string, newCert []byte) error
}
