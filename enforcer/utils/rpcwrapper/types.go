package rpcwrapper

import (
	"time"

	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/utils/tokens"
	"github.com/aporeto-inc/trireme/policy"
)

var gobTypes = []interface{}{
	InitRequestPayload{},
	InitResponsePayload{},
	InitSupervisorPayload{},
	EnforcePayload{},
	UnEnforcePayload{},
	SuperviseRequestPayload{},
	UnSupervisePayload{},
}

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
	FqConfig   *enforcer.FilterQueue
	MutualAuth bool
	Validity   time.Duration
	SecretType tokens.SecretsType
	ServerID   string
	CAPEM      []byte
	PublicPEM  []byte
	PrivatePEM []byte
}

//InitSupervisorPayload for supervisor init request
type InitSupervisorPayload struct {
	CaptureMethod CaptureType
}

// EnforcePayload Payload for enforce request
type EnforcePayload struct {
	ContextID        string
	ManagementID     string
	TriremeAction    policy.PUAction
	ApplicationACLs  *policy.IPRuleList
	NetworkACLs      *policy.IPRuleList
	Identity         *policy.TagsMap
	Annotations      *policy.TagsMap
	PolicyIPs        *policy.IPMap
	ReceiverRules    *policy.TagSelectorList
	TransmitterRules *policy.TagSelectorList
	PuPolicy         *policy.PUPolicy
	TriremeNetworks  []string
}

//SuperviseRequestPayload for Supervise request
type SuperviseRequestPayload struct {
	ContextID        string
	ManagementID     string
	TriremeAction    policy.PUAction
	ApplicationACLs  *policy.IPRuleList
	NetworkACLs      *policy.IPRuleList
	PolicyIPs        *policy.IPMap
	Identity         *policy.TagsMap
	Annotations      *policy.TagsMap
	ReceiverRules    *policy.TagSelectorList
	TransmitterRules *policy.TagSelectorList
	PuPolicy         *policy.PUPolicy
	ExcludedIP       []string
	TriremeNetworks  []string
}

//UnEnforcePayload payload for unenforce request
type UnEnforcePayload struct {
	ContextID string
}

//UnSupervisePayload payload for unsupervise request
type UnSupervisePayload struct {
	ContextID string
}

//InitResponsePayload Response payload
type InitResponsePayload struct {
	Status int
}

//EnforceResponsePayload exported
type EnforceResponsePayload struct {
	Status int
}

//SuperviseResponsePayload exported
type SuperviseResponsePayload struct {
	Status int
}

//UnEnforceResponsePayload exported
type UnEnforceResponsePayload struct {
	Status int
}

//StatsPayload is the payload carries by the stats reporting form the remote enforcer
type StatsPayload struct {
	NumFlows int
	Flows    []enforcer.StatsPayload
}

//ExcludeIPRequestPayload carries the list of excluded ips
type ExcludeIPRequestPayload struct {
	Ip []string
}
