package datapath

import (
	"github.com/aporeto-inc/trireme-lib/collector"
	"github.com/aporeto-inc/trireme-lib/enforcer/connection"
	"github.com/aporeto-inc/trireme-lib/enforcer/pucontext"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme-lib/policy"
)

func (d *Datapath) reportAcceptedFlow(p *packet.Packet, conn *connection.TCPConnection, sourceID string, destID string, context *pucontext.PUContext, report *policy.FlowPolicy, packet *policy.FlowPolicy) {
	if conn != nil {
		conn.SetReported(connection.AcceptReported)
	}
	d.reportFlow(p, conn, sourceID, destID, context, "", report, packet)
}

func (d *Datapath) reportRejectedFlow(p *packet.Packet, conn *connection.TCPConnection, sourceID string, destID string, context *pucontext.PUContext, mode string, report *policy.FlowPolicy, packet *policy.FlowPolicy) {
	if conn != nil && mode == collector.PolicyDrop {
		conn.SetReported(connection.RejectReported)
	}

	if report == nil {
		report = &policy.FlowPolicy{
			Action:   policy.Reject,
			PolicyID: "",
		}
	}
	d.reportFlow(p, conn, sourceID, destID, context, mode, report, packet)
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
		src.ID = context.ManagementID()
		src.Type = collector.PU
		dst.ID = flowpolicy.ServiceID
		dst.Type = collector.Address
	} else {
		src.ID = flowpolicy.ServiceID
		src.Type = collector.Address
		dst.ID = context.ManagementID()
		dst.Type = collector.PU
	}

	record := &collector.FlowRecord{
		ContextID:   context.ID(),
		Source:      src,
		Destination: dst,
		DropReason:  collector.PolicyDrop,
		Action:      flowpolicy.Action,
		Tags:        context.Annotations(),
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
		src.ID = context.ManagementID()
		src.Type = collector.PU
		dst.ID = flowpolicy.ServiceID
		dst.Type = collector.Address
	} else {
		src.ID = flowpolicy.ServiceID
		src.Type = collector.Address
		dst.ID = context.ManagementID()
		dst.Type = collector.PU
	}

	record := &collector.FlowRecord{
		ContextID:   context.ID(),
		Source:      src,
		Destination: dst,
		DropReason:  collector.PolicyDrop,
		Action:      flowpolicy.Action,
		Tags:        context.Annotations(),
		PolicyID:    flowpolicy.PolicyID,
	}

	d.collector.CollectFlowEvent(record)
}
