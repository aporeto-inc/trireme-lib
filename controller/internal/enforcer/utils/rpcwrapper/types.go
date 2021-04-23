package rpcwrapper

import (
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packettracing"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/controller/runtime"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

// CaptureType identifies the type of iptables implementation that should be used
type CaptureType int

const (
	// IPTables forces an IPTables implementation
	IPTables CaptureType = iota
	// IPSets forces an IPSet implementation
	IPSets
)

// PayloadType is the type of payload in the request.
type PayloadType int

// Payload report types.
const (
	PacketReport PayloadType = iota
	DNSReport
	CounterReport
	PingReport
	ConnectionExceptionReport
)

//Request exported
type Request struct {
	HashAuth    []byte
	PayloadType PayloadType
	Payload     interface{}
}

//exported consts from the package
const (
	SUCCESS = 0
)

//Response is the response for every RPC call. This is used to carry the status of the actual function call
//made on the remote end
type Response struct {
	Status  string
	Payload interface{} `json:",omitempty"`
}

//InitRequestPayload Payload for enforcer init request
type InitRequestPayload struct {
	MutualAuth             bool                   `json:",omitempty"`
	PacketLogs             bool                   `json:",omitempty"`
	Validity               time.Duration          `json:",omitempty"`
	ServerID               string                 `json:",omitempty"`
	ExternalIPCacheTimeout time.Duration          `json:",omitempty"`
	Secrets                secrets.RPCSecrets     `json:",omitempty"`
	Configuration          *runtime.Configuration `json:",omitempty"`
	BinaryTokens           bool                   `json:",omitempty"`
	IsBPFEnabled           bool                   `json:",omitempty"`
	IPv6Enabled            bool                   `json:",omitempty"`
	IPTablesLockfile       string                 `json:",omitempty"`
	ServiceMeshType        policy.ServiceMesh     `json:",omitempty"`
}

// UpdateSecretsPayload payload for the update secrets to remote enforcers
type UpdateSecretsPayload struct {
	Secrets secrets.RPCSecrets `json:",omitempty"`
}

// EnforcePayload Payload for enforce request
type EnforcePayload struct {
	ContextID string                 `json:",omitempty"`
	Policy    *policy.PUPolicyPublic `json:",omitempty"`
	Secrets   secrets.RPCSecrets     `json:",omitempty"`
}

//UnEnforcePayload payload for unenforce request
type UnEnforcePayload struct {
	ContextID string `json:",omitempty"`
}

//SetLogLevelPayload payload for set log level request
type SetLogLevelPayload struct {
	Level constants.LogLevel `json:",omitempty"`
}

//StatsPayload is the payload carries by the stats reporting form the remote enforcer
type StatsPayload struct {
	Flows map[uint64]*collector.FlowRecord `json:",omitempty"`
	Users map[string]*collector.UserRecord `json:",omitempty"`
}

// ReportPayload is the generic report from remote enforcer
type ReportPayload struct {
	Type    PayloadType
	Payload interface{}
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

// TokenRequestPayload carries the payload for issuing tokens.
type TokenRequestPayload struct {
	ContextID        string                  `json:",omitempty"`
	Audience         string                  `json:",omitempty"`
	Validity         time.Duration           `json:",omitempty"`
	ServiceTokenType common.ServiceTokenType `json:",omitempty"`
}

// TokenResponsePayload returns the issued token.
type TokenResponsePayload struct {
	Token string `json:",omitempty"`
}

// PingPayload represents the payload for ping config.
type PingPayload struct {
	ContextID  string
	PingConfig *policy.PingConfig
}

// DebugCollectPayload is the payload for the DebugCollect request.
type DebugCollectPayload struct {
	ContextID    string
	PcapFilePath string
	PcapFilter   string
	CommandExec  string
}

// DebugCollectResponsePayload is the payload for the DebugCollect response.
type DebugCollectResponsePayload struct {
	ContextID     string
	PID           int
	CommandOutput string
}
