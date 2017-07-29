package enforcer

import (
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer/lookup"
	"github.com/aporeto-inc/trireme/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme/policy"
)

func (d *Datapath) reportFlow(p *packet.Packet, connection *TCPConnection, sourceID string, destID string, context *PUContext, action string, mode string, plc *policy.FlowPolicy) {

	c := &collector.FlowRecord{
		ContextID: context.ID,
		Source: &collector.EndPoint{
			ID:   sourceID,
			IP:   p.SourceAddress.String(),
			Port: p.SourcePort,
			Type: collector.PU,
		},
		Destination: &collector.EndPoint{
			ID:   destID,
			IP:   p.DestinationAddress.String(),
			Port: p.DestinationPort,
			Type: collector.PU,
		},
		Tags:       context.Annotations,
		Action:     action,
		DropReason: mode,
	}

	if plc != nil {
		c.PolicyID = plc.PolicyID
		c.Encrypted = plc.Action.Encrypted()
	}

	d.collector.CollectFlowEvent(c)

}

func (d *Datapath) reportAcceptedFlow(p *packet.Packet, conn *TCPConnection, sourceID string, destID string, context *PUContext, plc *policy.FlowPolicy) {
	if conn != nil {
		conn.SetReported(RejectReported)
	}
	d.reportFlow(p, conn, sourceID, destID, context, collector.FlowAccept, "NA", plc)
}

func (d *Datapath) reportRejectedFlow(p *packet.Packet, conn *TCPConnection, sourceID string, destID string, context *PUContext, mode string, plc *policy.FlowPolicy) {
	if conn != nil {
		conn.SetReported(AcceptReported)
	}
	d.reportFlow(p, conn, sourceID, destID, context, collector.FlowReject, mode, plc)
}

func (d *Datapath) reportExternalServiceFlow(context *PUContext, flowpolicy *policy.FlowPolicy, app bool, p *packet.Packet) {

	src := &collector.EndPoint{
		IP:   p.SourceAddress.String(),
		Port: p.SourcePort,
	}

	dst := &collector.EndPoint{
		IP:   p.DestinationAddress.String(),
		Port: p.DestinationPort,
	}

	flowAction := collector.FlowAccept
	if flowpolicy == nil || flowpolicy.Action&policy.Accept == 0 {
		flowAction = collector.FlowReject
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
		Action:      flowAction,
		Tags:        context.Annotations,
		PolicyID:    flowpolicy.PolicyID,
	}

	d.collector.CollectFlowEvent(record)
}

func (d *Datapath) reportReverseExternalServiceFlow(context *PUContext, flowpolicy *policy.FlowPolicy, app bool, p *packet.Packet) {

	src := &collector.EndPoint{
		IP:   p.DestinationAddress.String(),
		Port: p.DestinationPort,
	}

	dst := &collector.EndPoint{
		IP:   p.SourceAddress.String(),
		Port: p.SourcePort,
	}

	flowAction := collector.FlowAccept
	if flowpolicy == nil || flowpolicy.Action&policy.Accept == 0 {
		flowAction = collector.FlowReject
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
		Action:      flowAction,
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
