package rpcwrapper

import (
	"time"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme/policy"
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
	FqConfig   *enforcer.FilterQueue      `json:",omitempty"`
	MutualAuth bool                       `json:",omitempty"`
	Validity   time.Duration              `json:",omitempty"`
	SecretType secrets.PrivateSecretsType `json:",omitempty"`
	ServerID   string                     `json:",omitempty"`
	CAPEM      []byte                     `json:",omitempty"`
	PublicPEM  []byte                     `json:",omitempty"`
	PrivatePEM []byte                     `json:",omitempty"`
	Token      []byte                     `json:",omitempty"`
}

//InitSupervisorPayload for supervisor init request
type InitSupervisorPayload struct {
	TriremeNetworks []string    `json:",omitempty"`
	CaptureMethod   CaptureType `json:",omitempty"`
}

// EnforcePayload Payload for enforce request
type EnforcePayload struct {
	ContextID        string                  `json:",omitempty"`
	ManagementID     string                  `json:",omitempty"`
	TriremeAction    policy.PUAction         `json:",omitempty"`
	ApplicationACLs  *policy.IPRuleList      `json:",omitempty"`
	NetworkACLs      *policy.IPRuleList      `json:",omitempty"`
	Identity         *policy.TagsMap         `json:",omitempty"`
	Annotations      *policy.TagsMap         `json:",omitempty"`
	PolicyIPs        *policy.IPMap           `json:",omitempty"`
	ReceiverRules    *policy.TagSelectorList `json:",omitempty"`
	TransmitterRules *policy.TagSelectorList `json:",omitempty"`
	TriremeNetworks  []string                `json:",omitempty"`
	ExcludedNetworks []string                `json:",omitempty"`
}

//SuperviseRequestPayload for Supervise request
type SuperviseRequestPayload struct {
	ContextID        string                  `json:",omitempty"`
	ManagementID     string                  `json:",omitempty"`
	TriremeAction    policy.PUAction         `json:",omitempty"`
	ApplicationACLs  *policy.IPRuleList      `json:",omitempty"`
	NetworkACLs      *policy.IPRuleList      `json:",omitempty"`
	PolicyIPs        *policy.IPMap           `json:",omitempty"`
	Identity         *policy.TagsMap         `json:",omitempty"`
	Annotations      *policy.TagsMap         `json:",omitempty"`
	ReceiverRules    *policy.TagSelectorList `json:",omitempty"`
	TransmitterRules *policy.TagSelectorList `json:",omitempty"`
	ExcludedNetworks []string                `json:",omitempty"`
	TriremeNetworks  []string                `json:",omitempty"`
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
}

//ExcludeIPRequestPayload carries the list of excluded ips
type ExcludeIPRequestPayload struct {
	IPs []string `json:",omitempty"`
}
