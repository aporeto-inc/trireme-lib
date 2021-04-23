package collector

import (
	"fmt"
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packettracing"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/gaia"
)

// Flow event description
const (
	// FlowReject indicates that a flow was rejected
	FlowReject = "reject"
	// FlowAccept logs that a flow is accepted
	FlowAccept = "accept"
	// MissingToken indicates that the token was missing
	MissingToken = "missingtoken"
	// InvalidToken indicates that the token was invalid
	InvalidToken = "token"
	// InvalidFormat indicates that the packet metadata were not correct
	InvalidFormat = "format"
	// InvalidHeader indicates that the TCP header was not there.
	InvalidHeader = "header"
	// InvalidPayload indicates that the TCP payload was not there or bad.
	InvalidPayload = "payload"
	// InvalidContext indicates that there was no context in the metadata
	InvalidContext = "context"
	// InvalidConnection indicates that there was no connection found
	InvalidConnection = "connection"
	// InvalidState indicates that a packet was received without proper state information
	InvalidState = "state"
	// InvalidNonse indicates that the nonse check failed
	InvalidNonse = "nonse"
	// PolicyDrop indicates that the flow is rejected because of the policy decision
	PolicyDrop = "policy"
	// APIPolicyDrop indicates that the request was dropped because of failed API validation.
	APIPolicyDrop = "api"
	// UnableToDial indicates that the proxy cannot dial out the connection
	UnableToDial = "dial"
	// CompressedTagMismatch indicates that the compressed tag version is dissimilar
	CompressedTagMismatch = "compressedtagmismatch"
	// EncryptionMismatch indicates that the policy encryption varies between client and server enforcer
	EncryptionMismatch = "encryptionmismatch"
	// DatapathVersionMismatch indicates that the datapath version is dissimilar
	DatapathVersionMismatch = "datapathversionmismatch"
	// PacketDrop indicate a single packet drop
	PacketDrop = "packetdrop"
)

// Container event description
const (
	// ContainerStart indicates a container start event
	ContainerStart = "start"
	// ContainerStop indicates a container stop event
	ContainerStop = "stop"
	// ContainerCreate indicates a container create event
	ContainerCreate = "create"
	// ContainerDelete indicates a container delete event
	ContainerDelete = "delete"
	// ContainerUpdate indicates a container policy update event
	ContainerUpdate = "update"
	// ContainerFailed indicates an event that a container was stopped because of policy issues
	ContainerFailed = "forcestop"
	// ContainerIgnored indicates that the container will be ignored by Trireme
	ContainerIgnored = "ignore"
	// ContainerDeleteUnknown indicates that policy for an unknown  container was deleted
	ContainerDeleteUnknown = "unknowncontainer"
)

const (
	// PolicyValid Normal flow accept
	PolicyValid = "V"
	// DefaultEndPoint  provides a string for unknown container sources
	DefaultEndPoint = "default"
	// SomeClaimsSource provides a string for some claims flow source.
	SomeClaimsSource = "some-claims"
)

// EventCollector is the interface for collecting events.
type EventCollector interface {

	// CollectFlowEvent collect a  flow event.
	CollectFlowEvent(record *FlowRecord)

	// CollectContainerEvent collects a container events
	CollectContainerEvent(record *ContainerRecord)

	// CollectUserEvent  collects a user event
	CollectUserEvent(record *UserRecord)

	// CollectTraceEvent collects a set of trace messages generated with Iptables trace command
	CollectTraceEvent(records []string)

	// CollectPacketEvent collects packet event from nfqdatapath
	CollectPacketEvent(report *PacketReport)

	// CollectCounterEvent collects the counters from
	CollectCounterEvent(counterReport *CounterReport)

	// CollectDNSRequests collects the dns requests
	CollectDNSRequests(request *DNSRequestReport)

	// CollectPingEvent collects the ping events
	CollectPingEvent(report *PingReport)

	// CollectConnectionExceptionReport collects the connection exception report
	CollectConnectionExceptionReport(report *ConnectionExceptionReport)
}

// EndPointType is the type of an endpoint (PU or an external IP address )
type EndPointType byte

const (
	// EndPointTypeExternalIP indicates that the endpoint is an external IP address
	EndPointTypeExternalIP EndPointType = iota
	// EndPointTypePU indicates that the endpoint is a PU.
	EndPointTypePU
	// EndPointTypeClaims indicates that the endpoint is of type claims.
	EndPointTypeClaims
)

func (e *EndPointType) String() string {

	switch *e {
	case EndPointTypeExternalIP:
		return "ext"
	case EndPointTypePU:
		return "pu"
	case EndPointTypeClaims:
		return "claims"
	}

	return "pu" // backward compatibility (CS: 04/24/2018)
}

// EndPoint is a structure that holds all the endpoint information
type EndPoint struct {
	ID         string
	IP         string
	URI        string
	HTTPMethod string
	UserID     string
	Type       EndPointType
	Port       uint16
}

// FlowRecord describes a flow record for statistis
type FlowRecord struct {
	ContextID             string
	Namespace             string
	Source                EndPoint
	Destination           EndPoint
	Tags                  []string
	DropReason            string
	PolicyID              string
	ObservedPolicyID      string
	ServiceType           policy.ServiceType
	ServiceID             string
	Count                 int
	Action                policy.ActionType
	ObservedAction        policy.ActionType
	ObservedActionType    policy.ObserveActionType
	L4Protocol            uint8
	SourceController      string
	DestinationController string
	RuleName              string
}

func (f *FlowRecord) String() string {
	return fmt.Sprintf("<flowrecord contextID:%s namespace:%s count:%d sourceID:%s destinationID:%s sourceIP: %s destinationIP:%s destinationPort:%d action:%s mode:%s>",
		f.ContextID,
		f.Namespace,
		f.Count,
		f.Source.ID,
		f.Destination.ID,
		f.Source.IP,
		f.Destination.IP,
		f.Destination.Port,
		f.Action.String(),
		f.DropReason,
	)
}

// ContainerRecord is a statistics record for a container
type ContainerRecord struct {
	ContextID string
	IPAddress policy.ExtendedMap
	Tags      *policy.TagStore
	Event     string
}

// UserRecord reports a new user access. These will be reported
// periodically.
type UserRecord struct {
	ID        string
	Namespace string
	Claims    []string
}

// PacketReport is the struct which is used to report packets captured in datapath
type PacketReport struct {
	TCPFlags        int
	Claims          []string
	DestinationIP   string
	DestinationPort int
	DropReason      string
	Encrypt         bool
	Event           packettracing.PacketEvent
	Length          int
	Mark            int
	Namespace       string
	PacketID        int
	Protocol        int
	PUID            string
	SourceIP        string
	SourcePort      int
	TriremePacket   bool
	Timestamp       int64
	Payload         []byte
}

// DNSRequestReport object is used to report dns requests being made by PU's
type DNSRequestReport struct {
	ContextID   string
	Namespace   string
	Source      *EndPoint
	Destination *EndPoint
	NameLookup  string
	Error       string
	Count       int
	Ts          time.Time
	IPs         []string
}

// Counters represent a single entry with name and current val
type Counters uint32

// CounterReport is called from the PU which reports Counters from the datapath
type CounterReport struct {
	Namespace string
	PUID      string
	Timestamp int64
	Counters  []Counters
}

// PingReport represents a single ping report from datapath.
type PingReport struct {
	PingID               string
	IterationID          int
	Type                 gaia.PingProbeTypeValue
	PUID                 string
	Namespace            string
	FourTuple            string
	RTT                  string
	Protocol             int
	ServiceType          string
	PayloadSize          int
	PayloadSizeType      gaia.PingProbePayloadSizeTypeValue
	PolicyID             string
	PolicyAction         policy.ActionType
	AgentVersion         string
	ApplicationListening bool
	SeqNum               uint32
	TargetTCPNetworks    bool
	ExcludedNetworks     bool
	Error                string
	Claims               []string
	ClaimsType           gaia.PingProbeClaimsTypeValue
	ACLPolicyID          string
	ACLPolicyAction      policy.ActionType
	PeerCertIssuer       string
	PeerCertSubject      string
	PeerCertExpiry       time.Time
	IsServer             bool
	ServiceID            string

	// Remote pu fields.
	RemoteController    string
	RemotePUID          string
	RemoteEndpointType  EndPointType
	RemoteNamespace     string
	RemoteNamespaceType gaia.PingProbeRemoteNamespaceTypeValue
}

// IPTablesTrace is a bundle of iptables trace records
type IPTablesTrace struct {
	Namespace string
	Timestamp int64
	Records   []*IPTablesTraceRecord
}

// IPTablesTraceRecord is the info parsed out from a trace event message
type IPTablesTraceRecord struct {
	TTL                  int
	Chain                string
	DestinationIP        string
	DestinationInterface string
	DestinationPort      int
	Length               int
	PacketID             int
	Protocol             int
	RuleID               int
	SourceIP             string
	SourceInterface      string
	SourcePort           int
	TableName            string
}

// ConnectionExceptionReport represents a single connection exception report from datapath.
type ConnectionExceptionReport struct {
	Timestamp       time.Time
	PUID            string
	Namespace       string
	Protocol        int
	SourceIP        string
	DestinationIP   string
	DestinationPort uint16
	State           string
	Reason          string
	Value           uint32
}
