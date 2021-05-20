package policy

import (
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"strings"

	"github.com/docker/go-connections/nat"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/utils/portspec"
	"go.aporeto.io/gaia"
	"go.uber.org/zap"
)

// Aporeto tag key and value constants
const (
	TagKeyController = "$controller"
	TagKeyID         = "$id"
	TagKeyIdentity   = "$identity"

	TagValueProcessingUnit = "processingunit"
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
	ObserveAction   ObserveActionType
	Action          ActionType
	ServiceID       string
	PolicyID        string
	RuleName        string
	Labels          []string
	ServicePriority uint32 // A hash of the ServiceID
	Priority        uint32 // Priority based on the ExternalNetwork entries
}

// Clone creates a copy of the FlowPolicy
func (f *FlowPolicy) Clone() *FlowPolicy {
	clone := &FlowPolicy{
		ObserveAction:   f.ObserveAction,
		Action:          f.Action,
		ServiceID:       f.ServiceID,
		PolicyID:        f.PolicyID,
		RuleName:        f.RuleName,
		Labels:          f.Labels,
		ServicePriority: f.ServicePriority,
		Priority:        f.Priority,
	}
	return clone
}

// LogPrefix is the prefix used in nf-log action. It must be less than
func (f *FlowPolicy) LogPrefix(contextID string) string {

	hash, err := Fnv32Hash(contextID)
	if err != nil {
		zap.L().Warn("unable to generate log prefix hash", zap.Error(err))
	}

	ruleExtNetName, _ := f.GetShortAndLongLogPrefix()
	return hash + ":" + ruleExtNetName + ":" + f.EncodedActionString()
}

// LogPrefixAction is the prefix used in nf-log action with the given action.
// NOTE: If 0 or empty action is passed, the default is reject (6).
func (f *FlowPolicy) LogPrefixAction(contextID string, action string) string {

	hash, err := Fnv32Hash(contextID)
	if err != nil {
		zap.L().Warn("unable to generate log prefix hash", zap.Error(err))
	}

	if len(action) == 0 || action == "0" {
		action = "6"
	}

	ruleExtNetName, _ := f.GetShortAndLongLogPrefix()
	return hash + ":" + ruleExtNetName + ":" + action
}

// DefaultLogPrefix return the prefix used in nf-log action for default rule.
func DefaultLogPrefix(contextID string, action ActionType) string {

	hash, err := Fnv32Hash(contextID)
	if err != nil {
		zap.L().Warn("unable to generate log prefix hash", zap.Error(err))
	}

	if action.Accepted() {
		return hash + ":default:default:3"
	}

	return hash + ":default:default:6"
}

// DefaultDropPacketLogPrefix generates the nflog prefix for packets logged by the catch all default rule
func DefaultDropPacketLogPrefix(contextID string) string {

	hash, err := Fnv32Hash(contextID)
	if err != nil {
		zap.L().Warn("unable to generate log prefix hash", zap.Error(err))
	}

	return hash + ":default:default:10"
}

// DefaultAction generates the default action of the rule
func DefaultAction(action ActionType) string {
	if action.Accepted() {
		return "ACCEPT"
	}
	return "DROP"
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

// GetShortAndLongLogPrefix returns the short and long log prefix
func (f *FlowPolicy) GetShortAndLongLogPrefix() (string, string) {

	getFirstXChars := func(str string, numChars int) string {
		if len(str) <= numChars {
			return str
		}
		return str[0:numChars]
	}

	getLastXChars := func(str string, numChars int) string {
		strLen := len(str)
		if strLen <= numChars {
			return str
		}
		index := strLen - numChars
		return str[index:]
	}

	// If we don't have a rulename, then do it the old way
	if (len(f.RuleName)) <= 0 {
		prefix := f.PolicyID + ":" + f.ServiceID
		return prefix, prefix
	}

	// The shortPrefix will become a key in a map we use to look up the long prefix.
	// I want to put as much of the info in the short logging prefix as possible to help
	// with debugging, but it needs to be unique
	hash, err := Fnv32Hash(f.PolicyID, f.ServiceID, f.RuleName)
	if err != nil {
		zap.L().Warn("unable to generate log prefix hash", zap.Error(err))
	}

	longPrefix := f.PolicyID + ":" + f.ServiceID + ":" + f.RuleName

	// We have 64 characters max for the logging prefix.
	// The ContextHash and Action are appended else where
	// ContextHash(10):PolicyID(10):ServiceID(10):RuleName(10)_hash(10):Action(2) = a max of 57 chars

	var builder strings.Builder
	builder.WriteString(getLastXChars(f.PolicyID, 10))
	builder.WriteString(":")
	builder.WriteString(getLastXChars(f.ServiceID, 10))
	builder.WriteString(":")
	builder.WriteString(getFirstXChars(f.RuleName, 10))
	builder.WriteString("_")
	builder.WriteString(hash)
	return builder.String(), longPrefix
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
	Addresses  []string
	Ports      []string
	Protocols  []string
	Extensions []string
	Policy     *FlowPolicy
}

// IPRuleList is a list of IP rules
type IPRuleList []IPRule

// PortProtocolPolicy holds the assicated ports, protocols and policy
type PortProtocolPolicy struct {
	Ports     []string
	Protocols []string
	Policy    *FlowPolicy
}

// DNSRuleList is a map from fqdns to a list of policies.
type DNSRuleList map[string][]PortProtocolPolicy

// Copy creates a clone of DNS rule list
func (l DNSRuleList) Copy() DNSRuleList {
	dnsRuleList := DNSRuleList{}

	// nolint:gosimple //S1001: should use copy() instead of a loop (gosimple) // false positive
	for k, v := range l {
		dnsRuleList[k] = v
	}

	return dnsRuleList
}

// Copy creates a clone of the IP rule list
func (l IPRuleList) Copy() IPRuleList {
	list := make(IPRuleList, len(l))

	// nolint:gosimple //S1001: should use copy() instead of a loop (gosimple) // false positive
	for i, v := range l {
		list[i] = v
	}

	return list
}

// KeyValueOperator describes an individual matchinggit  rule
type KeyValueOperator struct {
	Key       string
	Value     []string
	Operator  Operator
	ID        string
	PortRange *portspec.PortSpec
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

	// nolint:gosimple //S1001: should use copy() instead of a loop (gosimple) // false positive
	for i, v := range t {
		list[i] = v
	}

	return list
}

// ExtendedMap is a common map with additional functions
type ExtendedMap map[string]string

// Copy copies an ExtendedMap
func (s ExtendedMap) Copy() ExtendedMap {
	// nolint:gosimple //S1001: should use copy() instead of a loop (gosimple) // false positive
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

// DebugConfigInput holds information needed to start a debug collect.
type DebugConfigInput struct {
	DebugType   gaia.EnforcerRefreshDebugValue
	NativeID    string
	FilePath    string
	PcapFilter  string
	CommandExec string
}

// DebugConfigResult holds results from a debug collect.
type DebugConfigResult struct {
	PID           int
	CommandOutput string
}

// DebugConfig holds information needed for a single debug collect operation.
type DebugConfig struct {
	DebugConfigInput
	DebugConfigResult
}

// DebugConfigMulti holds information needed for a debug collect operation on all remote enforcers.
type DebugConfigMulti struct {
	DebugConfigInput
	Results map[string]*DebugConfigResult
}

// PingConfig holds the configuration to run ping.
type PingConfig struct {
	Mode               gaia.ProcessingUnitRefreshPingModeValue
	ID                 string
	IP                 net.IP
	Port               uint16
	Iterations         int
	TargetTCPNetworks  bool
	ExcludedNetworks   bool
	ServiceCertificate string
	ServiceKey         string
	ServiceAddresses   map[string][]string
}

// Ping Errors.
const (
	ErrExcludedNetworks  = "excludednetworks"
	ErrTargetTCPNetworks = "targettcpnetworks"
)

// Error returns error as string from ping config.
func (p *PingConfig) Error() string {

	switch {
	case p.ExcludedNetworks:
		return ErrExcludedNetworks
	case !p.TargetTCPNetworks:
		return ErrTargetTCPNetworks
	default:
		return ""
	}
}

// PingPayload holds the payload carried on the wire.
type PingPayload struct {
	PingID               string      `codec:",omitempty"`
	IterationID          int         `codec:",omitempty"`
	ApplicationListening bool        `codec:",omitempty"`
	NamespaceHash        string      `codec:",omitempty"`
	ServiceType          ServiceType `codec:",omitempty"`
}

// Fnv32Hash hash the given data by Fnv32-bit algorithm.
func Fnv32Hash(data ...string) (string, error) {

	if len(data) == 0 {
		return "", fmt.Errorf("no data to hash")
	}

	aggregatedData := ""
	for _, ed := range data {
		aggregatedData += ed
	}

	hash := fnv.New32()
	if _, err := hash.Write([]byte(aggregatedData)); err != nil {
		return "", fmt.Errorf("unable to hash data: %v", err)
	}

	return fmt.Sprintf("%d", hash.Sum32()), nil
}

// ServiceMesh to determine pod is of which servicemesh type
type ServiceMesh int

const (
	// None means the pod have no servicemesh enabled on it
	None ServiceMesh = iota
	// Istio servicemesh enabled on the pod
	Istio
)

func (s ServiceMesh) String() string {
	return [...]string{"None", "Istio"}[s]
}
