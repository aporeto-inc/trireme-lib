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

//Request exported
type Request struct {
	MethodIdentifier int
	HashAuth         []byte
	Payload          interface{}
}

//exported
const (
	SUCCESS      = 0
	StatsChannel = "/tmp/statschannel.sock"
)

//Response exported
type Response struct {
	MethodIdentifier int
	Status           error
}

//InitRequestPayload exported
type InitRequestPayload struct {
	FqConfig   enforcer.FilterQueue
	MutualAuth bool
	Validity   time.Duration
	SecretType tokens.SecretsType
	ContextID  string
	CAPEM      []byte
	PublicPEM  []byte
	PrivatePEM []byte
}

//InitSupervisorPayload exported
type InitSupervisorPayload struct {
	NetworkQueues     string
	ApplicationQueues string
	TargetNetworks    []string
}

// EnforcePayload exported
type EnforcePayload struct {
	ContextID        string
	ManagementID     string
	TriremeAction    policy.PUAction
	IngressACLs      *policy.IPRuleList
	EgressACLs       *policy.IPRuleList
	Identity         *policy.TagsMap
	Annotations      *policy.TagsMap
	PolicyIPs        *policy.IPMap
	ReceiverRules    *policy.TagSelectorList
	TransmitterRules *policy.TagSelectorList
	PuPolicy         *policy.PUPolicy
}

//SuperviseRequestPayload exported
type SuperviseRequestPayload struct {
	ContextID        string
	ManagementID     string
	TriremeAction    policy.PUAction
	IngressACLs      *policy.IPRuleList
	EgressACLs       *policy.IPRuleList
	PolicyIPs        *policy.IPMap
	Identity         *policy.TagsMap
	Annotations      *policy.TagsMap
	ReceiverRules    *policy.TagSelectorList
	TransmitterRules *policy.TagSelectorList
	PuPolicy         *policy.PUPolicy
}

//UnEnforcePayload exported
type UnEnforcePayload struct {
	ContextID string
}

//UnSupervisePayload exported
type UnSupervisePayload struct {
	ContextID string
}

//InitResponsePayload exported
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

type StatsPayload struct {
	NumFlows int
	Flows    []enforcer.StatsPayload
}
