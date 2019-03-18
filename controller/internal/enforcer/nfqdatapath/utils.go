package nfqdatapath

import (
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/policy"
)

func (d *Datapath) reportAcceptedFlow(p *packet.Packet, conn *connection.TCPConnection, sourceID string, destID string, context *pucontext.PUContext, report *policy.FlowPolicy, packet *policy.FlowPolicy, reverse bool) {
	if conn != nil {
		conn.SetReported(connection.AcceptReported)
	}

	if sourceID == destID {
		report = &policy.FlowPolicy{
			Action:   policy.Accept,
			PolicyID: "default",
		}
		packet = report
	}

	src, dst := d.generateEndpoints(p, sourceID, destID, reverse)

	d.reportFlow(p, src, dst, context, "", report, packet)
}

func (d *Datapath) reportRejectedFlow(p *packet.Packet, conn *connection.TCPConnection, sourceID string, destID string, context *pucontext.PUContext, mode string, report *policy.FlowPolicy, packet *policy.FlowPolicy, reverse bool) {
	if conn != nil && mode == collector.PolicyDrop {
		conn.SetReported(connection.RejectReported)
	}

	if report == nil {
		report = &policy.FlowPolicy{
			Action:   policy.Reject,
			PolicyID: "default",
		}
	}
	if packet == nil {
		packet = report
	}

	src, dst := d.generateEndpoints(p, sourceID, destID, reverse)

	d.reportFlow(p, src, dst, context, mode, report, packet)
}

func (d *Datapath) reportUDPAcceptedFlow(p *packet.Packet, conn *connection.UDPConnection, sourceID string, destID string, context *pucontext.PUContext, report *policy.FlowPolicy, packet *policy.FlowPolicy, reverse bool) {
	if conn != nil {
		conn.SetReported(connection.AcceptReported)
	}

	src, dst := d.generateEndpoints(p, sourceID, destID, reverse)

	d.reportFlow(p, src, dst, context, "", report, packet)
}

func (d *Datapath) reportUDPRejectedFlow(p *packet.Packet, conn *connection.UDPConnection, sourceID string, destID string, context *pucontext.PUContext, mode string, report *policy.FlowPolicy, packet *policy.FlowPolicy, reverse bool) {
	if conn != nil && mode == collector.PolicyDrop {
		conn.SetReported(connection.RejectReported)
	}

	if report == nil {
		report = &policy.FlowPolicy{
			Action:   policy.Reject,
			PolicyID: "default",
		}
	}
	if packet == nil {
		packet = report
	}

	src, dst := d.generateEndpoints(p, sourceID, destID, reverse)

	d.reportFlow(p, src, dst, context, mode, report, packet)
}

func (d *Datapath) reportExternalServiceFlowCommon(context *pucontext.PUContext, report *policy.FlowPolicy, actual *policy.FlowPolicy, app bool, p *packet.Packet, src, dst *collector.EndPoint) {

	if app {
		// TODO: report.ServiceID ????
		src.ID = context.ManagementID()
		src.Type = collector.EnpointTypePU
		dst.ID = report.ServiceID
		dst.Type = collector.EndPointTypeExternalIP
	} else {
		src.ID = report.ServiceID
		src.Type = collector.EndPointTypeExternalIP
		dst.ID = context.ManagementID()
		dst.Type = collector.EnpointTypePU
	}

	dropReason := ""
	if report.Action.Rejected() || actual.Action.Rejected() {
		dropReason = collector.PolicyDrop
	}

	record := &collector.FlowRecord{
		ContextID:   context.ID(),
		Source:      src,
		Destination: dst,
		DropReason:  dropReason,
		Action:      actual.Action,
		Tags:        context.Annotations(),
		PolicyID:    actual.PolicyID,
		L4Protocol:  p.IPProto(),
		Count:       1,
	}

	if report.ObserveAction.Observed() {
		record.ObservedAction = report.Action
		record.ObservedPolicyID = report.PolicyID
	}

	d.collector.CollectFlowEvent(record)
}

func (d *Datapath) reportExternalServiceFlow(context *pucontext.PUContext, report *policy.FlowPolicy, packet *policy.FlowPolicy, app bool, p *packet.Packet) {

	src := &collector.EndPoint{
		IP:   p.SourceAddress().String(),
		Port: p.SourcePort(),
	}

	dst := &collector.EndPoint{
		IP:   p.DestinationAddress().String(),
		Port: p.DestPort(),
	}

	d.reportExternalServiceFlowCommon(context, report, packet, app, p, src, dst)
}

func (d *Datapath) reportReverseExternalServiceFlow(context *pucontext.PUContext, report *policy.FlowPolicy, packet *policy.FlowPolicy, app bool, p *packet.Packet) {

	src := &collector.EndPoint{
		IP:   p.DestinationAddress().String(),
		Port: p.DestPort(),
	}

	dst := &collector.EndPoint{
		IP:   p.SourceAddress().String(),
		Port: p.SourcePort(),
	}

	d.reportExternalServiceFlowCommon(context, report, packet, app, p, src, dst)
}

func (d *Datapath) generateEndpoints(p *packet.Packet, sourceID string, destID string, reverse bool) (*collector.EndPoint, *collector.EndPoint) {

	src := &collector.EndPoint{
		ID:   sourceID,
		IP:   p.SourceAddress().String(),
		Port: p.SourcePort(),
		Type: collector.EnpointTypePU,
	}
	dst := &collector.EndPoint{
		ID:   destID,
		IP:   p.DestinationAddress().String(),
		Port: p.DestPort(),
		Type: collector.EnpointTypePU,
	}

	if reverse {
		return dst, src
	}

	return src, dst
}
