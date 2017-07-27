package enforcer

import (
	"fmt"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/enforcer/lookup"
	"github.com/aporeto-inc/trireme/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme/policy"
)

func (d *Datapath) reportFlow(p *packet.Packet, connection *TCPConnection, sourceID string, destID string, context *PUContext, action string, mode string) {

	d.collector.CollectFlowEvent(&collector.FlowRecord{
		ContextID:       context.ID,
		DestinationID:   destID,
		SourceID:        sourceID,
		Tags:            context.Annotations,
		Action:          action,
		Mode:            mode,
		SourceIP:        p.SourceAddress.String(),
		DestinationIP:   p.DestinationAddress.String(),
		DestinationPort: p.DestinationPort,
	})
}

func (d *Datapath) reportAcceptedFlow(p *packet.Packet, conn *TCPConnection, sourceID string, destID string, context *PUContext) {
	if conn != nil {
		conn.SetReported(RejectReported)
	}
	d.reportFlow(p, conn, sourceID, destID, context, collector.FlowAccept, "NA")
}

func (d *Datapath) reportRejectedFlow(p *packet.Packet, conn *TCPConnection, sourceID string, destID string, context *PUContext, mode string) {
	if conn != nil {
		conn.SetReported(AcceptReported)
	}
	d.reportFlow(p, conn, sourceID, destID, context, collector.FlowReject, mode)
}

func (d *Datapath) reportExternalServiceFlow(context *PUContext, flowpolicy *policy.FlowPolicy, app bool, p *packet.Packet) {

	flowAction := collector.FlowAccept
	if flowpolicy == nil || flowpolicy.Action&policy.Accept == 0 {
		flowAction = collector.FlowReject
	}

	fmt.Println("Here is the IPs and action ", p.DestinationAddress.String(), p.SourceAddress.String(), flowAction)

	record := &collector.FlowRecord{
		ContextID:       context.ID,
		Action:          flowAction,
		SourceIP:        p.SourceAddress.String(),
		DestinationIP:   p.DestinationAddress.String(),
		DestinationPort: p.DestinationPort,
		Tags:            context.Annotations,
	}

	if !app {
		record.Mode = "extsrc"
		record.SourceID = flowpolicy.ServiceID
		record.DestinationID = context.ManagementID
	} else {
		record.Mode = "extdst"
		record.SourceID = context.ManagementID
		record.DestinationID = flowpolicy.ServiceID
	}

	d.collector.CollectFlowEvent(record)
}

func (d *Datapath) reportReverseExternalServiceFlow(context *PUContext, flowpolicy *policy.FlowPolicy, app bool, p *packet.Packet) {

	flowAction := collector.FlowAccept
	if flowpolicy == nil || flowpolicy.Action&policy.Accept == 0 {
		flowAction = collector.FlowReject
	}

	fmt.Println("Here is the reverse IPs and action ", p.DestinationAddress.String(), p.SourceAddress.String(), flowAction)

	record := &collector.FlowRecord{
		ContextID:       context.ID,
		Action:          flowAction,
		SourceIP:        p.DestinationAddress.String(),
		DestinationIP:   p.SourceAddress.String(),
		DestinationPort: p.SourcePort,
		Tags:            context.Annotations,
	}

	if !app {
		record.Mode = "extsrc"
		record.SourceID = flowpolicy.ServiceID
		record.DestinationID = context.ManagementID
	} else {
		record.Mode = "extdst"
		record.SourceID = context.ManagementID
		record.DestinationID = flowpolicy.ServiceID
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
