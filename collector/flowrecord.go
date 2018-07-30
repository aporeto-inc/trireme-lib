package collector

import (
	"errors"
	"fmt"

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
