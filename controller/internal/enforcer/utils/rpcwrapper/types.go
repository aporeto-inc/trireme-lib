package rpcwrapper

import (
	"time"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
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
	SUCCESS      = 0
	StatsChannel = "/var/run/statschannel.sock"
)

//Response is the response for every RPC call. This is used to carry the status of the actual function call
//made on the remote end
type Response struct {
	Status string
}

//InitRequestPayload Payload for enforcer init request
type InitRequestPayload struct {
	FqConfig               *fqconfig.FilterQueue `json:",omitempty"`
	MutualAuth             bool                  `json:",omitempty"`
	PacketLogs             bool                  `json:",omitempty"`
	Validity               time.Duration         `json:",omitempty"`
	ServerID               string                `json:",omitempty"`
	ExternalIPCacheTimeout time.Duration         `json:",omitempty"`
	Secrets                secrets.PublicSecrets `json:",omitempty"`
	TargetNetworks         []string              `json:",omitempty"`
}

// UpdateSecretsPayload payload for the update secrets to remote enforcers
type UpdateSecretsPayload struct {
	Secrets secrets.PublicSecrets `json:",omitempty"`
}

//InitSupervisorPayload for supervisor init request
type InitSupervisorPayload struct {
	TriremeNetworks []string    `json:",omitempty"`
	CaptureMethod   CaptureType `json:",omitempty"`
}

// EnforcePayload Payload for enforce request
type EnforcePayload struct {
	ContextID string                 `json:",omitempty"`
	Policy    *policy.PUPolicyPublic `json:",omitempty"`
	Secrets   secrets.PublicSecrets  `json:",omitempty"`
}

//SuperviseRequestPayload for Supervise request
type SuperviseRequestPayload struct {
	ContextID string                 `json:",omitempty"`
	Policy    *policy.PUPolicyPublic `json:",omitempty"`
}

//UnEnforcePayload payload for unenforce request
type UnEnforcePayload struct {
	ContextID string `json:",omitempty"`
}

//UnSupervisePayload payload for unsupervise request
type UnSupervisePayload struct {
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

//SuperviseResponsePayload exported
type SuperviseResponsePayload struct {
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

//ExcludeIPRequestPayload carries the list of excluded ips
type ExcludeIPRequestPayload struct {
	IPs []string `json:",omitempty"`
}

//SetTargetNetworks carries the payload for target networks
type SetTargetNetworks struct {
	TargetNetworks []string `json:",omitempty"`
}
