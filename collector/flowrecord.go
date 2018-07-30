package collector

import (
	"errors"
	"fmt"

	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/policy"
)

// Errors returned from flow record creation.
var (
	ErrFlowRecordInvalidSrc      = errors.New("no source or missing source id")
	ErrFlowRecordInvalidDest     = errors.New("invalid pu context")
	ErrFlowRecordInvalidTags     = errors.New("missing tags")
	ErrFlowRecordInvalidProtocol = errors.New("missing namespace tag")
)

// FlowRecord describes a flow record for statistis
type FlowRecord struct {
	ContextID        string
	Source           *EndPoint
	Destination      *EndPoint
	Tags             *policy.TagStore
	DropReason       string
	PolicyID         string
	ObservedPolicyID string
	ServiceType      policy.ServiceType
	ServiceID        string
	Count            int
	Action           policy.ActionType
	ObservedAction   policy.ActionType
	L4Protocol       uint8
}

// FlowRecordOption is provided using functional arguments.
type FlowRecordOption func(*FlowRecord)

// OptionActionReject is an option to setup action as reject
func OptionActionReject(dropReason string) FlowRecordOption {
	return func(f *FlowRecord) {
		f.DropReason = dropReason
	}
}

// OptionObservedAction is an option to setup observed action
func OptionObservedAction(id string, action policy.ActionType) FlowRecordOption {
	return func(f *FlowRecord) {
		f.ObservedPolicyID = id
		f.ObservedAction = action
	}
}

// OptionService is an option to set service information
func OptionService(id string, t policy.ServiceType) FlowRecordOption {
	return func(f *FlowRecord) {
		f.ServiceID = id
		f.ServiceType = t
	}
}

// NewFlowRecord sets up a new flow record
func NewFlowRecord(ctxID string, source, dest *EndPoint, protocol uint8, tags *policy.TagStore, action policy.ActionType, opts ...FlowRecordOption) (*FlowRecord, error) {

	if source == nil || source.ID == "" {
		return nil, ErrFlowRecordInvalidSrc
	}

	if dest == nil || dest.ID == "" {
		return nil, ErrFlowRecordInvalidDest
	}

	if tags == nil {
		return nil, ErrFlowRecordInvalidTags
	}

	if protocol != packet.IPProtocolTCP && protocol != packet.IPProtocolUDP {
		return nil, ErrFlowRecordInvalidProtocol
	}

	r := &FlowRecord{
		ContextID:   ctxID,
		Source:      source,
		Destination: dest,
		Tags:        tags,
		Count:       1,
		Action:      action,
	}

	for _, opt := range opts {
		opt(r)
	}

	return r, nil
}

func (f *FlowRecord) String() string {
	return fmt.Sprintf("<flowrecord contextID:%s count:%d sourceID:%s destinationID:%s sourceIP: %s destinationIP:%s destinationPort:%d action:%s mode:%s>",
		f.ContextID,
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
