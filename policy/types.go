package policy

import (
	"errors"

	"github.com/docker/go-connections/nat"
	"go.aporeto.io/trireme-lib/common"
)

const (
	// DefaultNamespace is the default namespace for applying policy
	DefaultNamespace = "bridge"
)

// constants for various actions
const (
	actionReject      = "reject"
	actionAccept      = "accept"
	actionPassthrough = "passthrough"
	actionEncrypt     = "encrypt"
	actionLog         = "log"

	oactionContinue = "continue"
	oactionApply    = "apply"

	actionNone    = "none"
	actionUnknown = "unknown"
)

// Operator defines the operation between your key and value.
type Operator string

const (
	// Equal is the equal operator
	Equal = "="
	// NotEqual is the not equal operator
	NotEqual = "=!"
	// KeyExists is the key=* operator
	KeyExists = "*"
	// KeyNotExists means that the key doesnt exist in the incoming tags
	KeyNotExists = "!*"
)

// ActionType   is the action that can be applied to a flow.
type ActionType byte

// Accepted returns if the action mask contains the Accepted mask.
func (f ActionType) Accepted() bool {
	return f&Accept > 0
}

// Rejected returns if the action mask contains the Rejected mask.
func (f ActionType) Rejected() bool {
	return f&Reject > 0
}

// Encrypted returns if the action mask contains the Encrypted mask.
func (f ActionType) Encrypted() bool {
	return f&Encrypt > 0
}

// Logged returns if the action mask contains the Logged mask.
func (f ActionType) Logged() bool {
	return f&Log > 0
}

// Observed returns if the action mask contains the Observed mask.
func (f ActionType) Observed() bool {
	return f&Observe > 0
}

// ActionString returns if the action if accepted of rejected as a long string.
func (f ActionType) ActionString() string {
	if f.Accepted() && !f.Rejected() {
		return actionAccept
	}

	if !f.Accepted() && f.Rejected() {
		return actionReject
	}

	return actionPassthrough
}

func (f ActionType) String() string {
	switch f {
	case Accept:
		return actionAccept
	case Reject:
		return actionReject
	case Encrypt:
		return actionEncrypt
	case Log:
		return actionLog
	}

	return actionUnknown
}

const (
	// Accept is the accept action
	Accept ActionType = 0x1
	// Reject is the reject  action
	Reject ActionType = 0x2
	// Encrypt instructs data to be encrypted
	Encrypt ActionType = 0x4
	// Log instructs the datapath to log the IP addresses
	Log ActionType = 0x8
	// Observe instructs the datapath to observe policy results
	Observe ActionType = 0x10
)

// ObserveActionType is the action that can be applied to a flow for an observation rule.
type ObserveActionType byte

// Observed returns true if any observed action was found.
func (f ObserveActionType) Observed() bool {
	return f != ObserveNone
}

// ObserveContinue returns if the action of observation rule is continue.
func (f ObserveActionType) ObserveContinue() bool {
	return f&ObserveContinue > 0
}

// ObserveApply returns if the action of observation rule is allow.
func (f ObserveActionType) ObserveApply() bool {
	return f&ObserveApply > 0
}

func (f ObserveActionType) String() string {
	switch f {
	case ObserveNone:
		return actionNone
	case ObserveContinue:
		return oactionContinue
	case ObserveApply:
		return oactionApply
	}

	return actionUnknown
}

// Observe actions are used in conjunction with action.
const (
	// ObserveNone specifies if any observation was made or not.
	ObserveNone ObserveActionType = 0x0
	// ObserveContinue is used to not take any action on packet and is deferred to
	// an actual rule with accept or deny action.
	ObserveContinue ObserveActionType = 0x1
	// ObserveApply is used to apply action to packets hitting this rule.
	ObserveApply ObserveActionType = 0x2
)

// FlowPolicy captures the policy for a particular flow
type FlowPolicy struct {
	ObserveAction ObserveActionType
	Action        ActionType
	ServiceID     string
	PolicyID      string
	Labels        []string
}

// DefaultAcceptLogPrefix return the prefix used in nf-log action for default rule.
func DefaultAcceptLogPrefix(contextID string) string {
	return contextID + ":default:default" + "3"
}

// LogPrefix is the prefix used in nf-log action. It must be less than
func (f *FlowPolicy) LogPrefix(contextID string) string {
	prefix := contextID + ":" + f.PolicyID + ":" + f.ServiceID + f.EncodedActionString()
	return prefix
}

// DefaultLogPrefix return the prefix used in nf-log action for default rule.
func DefaultLogPrefix(contextID string) string {
	return contextID + ":default:default" + "6"
}

// EncodedActionString is used to encode observed action as well as action
func (f *FlowPolicy) EncodedActionString() string {

	var e string

	if f.Action.Accepted() && !f.Action.Rejected() {
		if f.ObserveAction.ObserveContinue() {
			e = "1"
		} else if f.ObserveAction.ObserveApply() {
			e = "2"
		} else {
			e = "3"
		}
	} else if !f.Action.Accepted() && f.Action.Rejected() {
		if f.ObserveAction.ObserveContinue() {
			e = "4"
		} else if f.ObserveAction.ObserveApply() {
			e = "5"
		} else {
			e = "6"
		}
	} else {
		if f.ObserveAction.ObserveContinue() {
			e = "7"
		} else if f.ObserveAction.ObserveApply() {
			e = "8"
		} else {
			e = "9"
		}
	}
	return e
}

// EncodedStringToAction returns action and observed action from encoded string.
func EncodedStringToAction(e string) (ActionType, ObserveActionType, error) {

	switch e {
	case "1":
		return Observe | Accept, ObserveContinue, nil
	case "2":
		return Observe | Accept, ObserveApply, nil
	case "3":
		return Accept, ObserveNone, nil
	case "4":
		return Observe | Reject, ObserveContinue, nil
	case "5":
		return Observe | Reject, ObserveApply, nil
	case "6":
		return Reject, ObserveNone, nil
	case "7":
		return Observe, ObserveContinue, nil
	case "8":
		return Observe, ObserveApply, nil
	case "9":
		return 0, ObserveNone, nil
	}

	return 0, 0, errors.New("Invalid encoding")
}

// IPRule holds IP rules to external services
type IPRule struct {
	Addresses []string
	Ports     []string
	Protocols []string
	Policy    *FlowPolicy
}

// IPRuleList is a list of IP rules
type IPRuleList []IPRule

// DNSRule holds the dns names and the assicated ports
type DNSRule struct {
	Name     string
	Port     string
	Protocol string
	Policy   *FlowPolicy
}

// DNSRuleList is a list of DNS rules
type DNSRuleList []DNSRule

// Copy creates a clone of DNS rule list
func (l DNSRuleList) Copy() DNSRuleList {
	list := make(DNSRuleList, len(l))

	for i, v := range l {
		list[i] = v
	}

	return list
}

// Copy creates a clone of the IP rule list
func (l IPRuleList) Copy() IPRuleList {
	list := make(IPRuleList, len(l))
	for i, v := range l {
		list[i] = v
	}
	return list
}

// KeyValueOperator describes an individual matching rule
type KeyValueOperator struct {
	Key      string
	Value    []string
	Operator Operator
	ID       string
}

// TagSelector info describes a tag selector key Operator value
type TagSelector struct {
	Clause []KeyValueOperator
	Policy *FlowPolicy
}

// TagSelectorList defines a list of TagSelectors
type TagSelectorList []TagSelector

// Copy  returns a copy of the TagSelectorList
func (t TagSelectorList) Copy() TagSelectorList {
	list := make(TagSelectorList, len(t))

	for i, v := range t {
		list[i] = v
	}

	return list
}

// ExtendedMap is a common map with additional functions
type ExtendedMap map[string]string

// Copy copies an ExtendedMap
func (s ExtendedMap) Copy() ExtendedMap {
	c := ExtendedMap{}
	for k, v := range s {
		c[k] = v
	}
	return c
}

// Get does a lookup in the map
func (s ExtendedMap) Get(key string) (string, bool) {
	value, ok := s[key]
	return value, ok
}

// OptionsType is a set of options that can be passed with a policy request
type OptionsType struct {
	// CgroupName is the name of the cgroup
	CgroupName string

	// CgroupMark is the tag of the cgroup
	CgroupMark string

	// UserID is the user ID if it exists
	UserID string

	// AutoPort option is set if auto port is enabled
	AutoPort bool

	// Services is the list of services of interest
	Services []common.Service

	// PolicyExtensions is policy resolution extensions
	PolicyExtensions interface{}

	// PortMap maps container port -> host ports.
	PortMap map[nat.Port][]string

	// ConvertedDockerPU is set when a docker PU is converted to LinuxProcess
	// in order to implement host network containers.
	ConvertedDockerPU bool
}

// RuntimeError is an error detected by the TriremeController that has to be
// returned at a later time to the policy engine to take action.
type RuntimeError struct {
	ContextID string
	Error     error
}
