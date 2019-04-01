package rpcwrapper

import (
	"time"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/packettracing"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
)

// CaptureType identifies the type of iptables implementation that should be used
type CaptureType int

const (
	// IPTables forces an IPTables implementation
	IPTables CaptureType = iota
	// IPSets forces an IPSet implementation
	IPSets
)

//Request exported
type Request struct {
	HashAuth []byte
	Payload  interface{}
}

//exported consts from the package
const (
	SUCCESS = 0
)

//Response is the response for every RPC call. This is used to carry the status of the actual function call
//made on the remote end
type Response struct {
	Status string
}

//InitRequestPayload Payload for enforcer init request
type InitRequestPayload struct {
	FqConfig               *fqconfig.FilterQueue  `json:",omitempty"`
	MutualAuth             bool                   `json:",omitempty"`
	PacketLogs             bool                   `json:",omitempty"`
	Validity               time.Duration          `json:",omitempty"`
	ServerID               string                 `json:",omitempty"`
	ExternalIPCacheTimeout time.Duration          `json:",omitempty"`
	Secrets                secrets.PublicSecrets  `json:",omitempty"`
	Configuration          *runtime.Configuration `json:",omitempty"`
}

// UpdateSecretsPayload payload for the update secrets to remote enforcers
type UpdateSecretsPayload struct {
	Secrets secrets.PublicSecrets `json:",omitempty"`
}

// EnforcePayload Payload for enforce request
type EnforcePayload struct {
	ContextID string                 `json:",omitempty"`
	Policy    *policy.PUPolicyPublic `json:",omitempty"`
	Secrets   secrets.PublicSecrets  `json:",omitempty"`
}

//UnEnforcePayload payload for unenforce request
type UnEnforcePayload struct {
	ContextID string `json:",omitempty"`
}

//InitResponsePayload Response payload
type InitResponsePayload struct {
	Status int `json:",omitempty"`
}

//EnforceResponsePayload exported
type EnforceResponsePayload struct {
	Status int `json:",omitempty"`
}

//UnEnforceResponsePayload exported
type UnEnforceResponsePayload struct {
	Status int `json:",omitempty"`
}

//StatsPayload is the payload carries by the stats reporting form the remote enforcer
type StatsPayload struct {
	Flows map[string]*collector.FlowRecord `json:",omitempty"`
	Users map[string]*collector.UserRecord `json:",omitempty"`
}

// DebugPacketPayload is the enforcer packet report from remote enforcers
type DebugPacketPayload struct {
	PacketRecords []*collector.PacketReport
}

//SetTargetNetworksPayload carries the payload for target networks
type SetTargetNetworksPayload struct {
	Configuration *runtime.Configuration `json:",omitempty"`
}

// EnableIPTablesPacketTracingPayLoad is the payload message to enable iptable trace in remote containers
type EnableIPTablesPacketTracingPayLoad struct {
	IPTablesPacketTracing bool          `json:",omitempty"`
	Interval              time.Duration `json:",omitempty"`
	ContextID             string        `json:",omitempty"`
}

// EnableDatapathPacketTracingPayLoad is the payload to enable nfq packet tracing in the remote container
type EnableDatapathPacketTracingPayLoad struct {
	Direction packettracing.TracingDirection `json:",omitempty"`
	Interval  time.Duration                  `json:",omitempty"`
	ContextID string                         `json:",omitempty"`
}
