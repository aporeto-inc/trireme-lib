package datapath

import (
	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/enforcer/connection"
	"github.com/aporeto-inc/trireme-lib/enforcer/lookup"
	"github.com/aporeto-inc/trireme-lib/enforcer/pucontext"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme-lib/policy"
)

func (d *Datapath) reportAcceptedFlow(p *packet.Packet, conn *connection.TCPConnection, sourceID string, destID string, context *pucontext.PUContext, plc *policy.FlowPolicy) {
	if conn != nil {
		conn.SetReported(connection.RejectReported)
	}
	d.reportFlow(p, conn, sourceID, destID, context, "", plc)
}

func (d *Datapath) reportRejectedFlow(p *packet.Packet, conn *connection.TCPConnection, sourceID string, destID string, context *pucontext.PUContext, mode string, plc *policy.FlowPolicy) {
	if conn != nil {
		conn.SetReported(connection.AcceptReported)
	}

	if plc == nil {
		plc = &policy.FlowPolicy{
			Action:   policy.Reject,
			PolicyID: "",
		}
	}
	d.reportFlow(p, conn, sourceID, destID, context, mode, plc)
}

func (d *Datapath) reportExternalServiceFlow(context *pucontext.PUContext, flowpolicy *policy.FlowPolicy, app bool, p *packet.Packet) {

	src := &collector.EndPoint{
		IP:   p.SourceAddress.String(),
		Port: p.SourcePort,
	}

	dst := &collector.EndPoint{
		IP:   p.DestinationAddress.String(),
		Port: p.DestinationPort,
	}

	if flowpolicy == nil {
		flowpolicy = &policy.FlowPolicy{
			Action:    policy.Reject,
			ServiceID: "default",
		}
	}

	if app {
		src.ID = context.ManagementID
		src.Type = collector.PU
		dst.ID = flowpolicy.ServiceID
		dst.Type = collector.Address
	} else {
		src.ID = flowpolicy.ServiceID
		src.Type = collector.Address
		dst.ID = context.ManagementID
		dst.Type = collector.PU
	}

	record := &collector.FlowRecord{
		ContextID:   context.ID,
		Source:      src,
		Destination: dst,
		DropReason:  collector.PolicyDrop,
		Action:      flowpolicy.Action,
		Tags:        context.Annotations,
		PolicyID:    flowpolicy.PolicyID,
	}

	d.collector.CollectFlowEvent(record)
}

func (d *Datapath) reportReverseExternalServiceFlow(context *pucontext.PUContext, flowpolicy *policy.FlowPolicy, app bool, p *packet.Packet) {

	src := &collector.EndPoint{
		IP:   p.DestinationAddress.String(),
		Port: p.DestinationPort,
	}

	dst := &collector.EndPoint{
		IP:   p.SourceAddress.String(),
		Port: p.SourcePort,
	}

	if flowpolicy == nil {
		flowpolicy = &policy.FlowPolicy{
			Action:    policy.Reject,
			ServiceID: "default",
		}
	}

	if app {
		src.ID = context.ManagementID
		src.Type = collector.PU
		dst.ID = flowpolicy.ServiceID
		dst.Type = collector.Address
	} else {
		src.ID = flowpolicy.ServiceID
		src.Type = collector.Address
		dst.ID = context.ManagementID
		dst.Type = collector.PU
	}

	record := &collector.FlowRecord{
		ContextID:   context.ID,
		Source:      src,
		Destination: dst,
		DropReason:  collector.PolicyDrop,
		Action:      flowpolicy.Action,
		Tags:        context.Annotations,
		PolicyID:    flowpolicy.PolicyID,
	}

	d.collector.CollectFlowEvent(record)
}

// createRuleDBs creates the database of rules from the policy
func createRuleDBs(policyRules policy.TagSelectorList) (*lookup.PolicyDB, *lookup.PolicyDB) {

	acceptRules := lookup.NewPolicyDB()
	rejectRules := lookup.NewPolicyDB()

	for _, rule := range policyRules {
		if rule.Policy.Action&policy.Accept != 0 {
			acceptRules.AddPolicy(rule)
		} else if rule.Policy.Action&policy.Reject != 0 {
			rejectRules.AddPolicy(rule)
		} else {
			continue
		}
	}
	return acceptRules, rejectRules
}
