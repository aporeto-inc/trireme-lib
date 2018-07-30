package nfqdatapath

import (
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/policy"
)

func (d *Datapath) reportAcceptedFlow(p *packet.Packet, conn *connection.TCPConnection, sourceID string, destID string, context *pucontext.PUContext, report *policy.FlowPolicy, packet *policy.FlowPolicy) {
	if conn != nil {
		conn.SetReported(connection.AcceptReported)
	}
	d.reportFlow(p, sourceID, destID, context, "", report, packet)
}

func (d *Datapath) reportUDPAcceptedFlow(p *packet.Packet, conn *connection.UDPConnection, sourceID string, destID string, context *pucontext.PUContext, report *policy.FlowPolicy, packet *policy.FlowPolicy) {
	if conn != nil {
		conn.SetReported(connection.AcceptReported)
	}
	d.reportFlow(p, sourceID, destID, context, "", report, packet)
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
	if packet == nil {
		packet = report
	}
	d.reportFlow(p, sourceID, destID, context, mode, report, packet)
}

func (d *Datapath) reportUDPRejectedFlow(p *packet.Packet, conn *connection.UDPConnection, sourceID string, destID string, context *pucontext.PUContext, mode string, report *policy.FlowPolicy, packet *policy.FlowPolicy) {
	if conn != nil && mode == collector.PolicyDrop {
		conn.SetReported(connection.RejectReported)
	}

	if report == nil {
		report = &policy.FlowPolicy{
			Action:   policy.Reject,
			PolicyID: "",
		}
	}
	if packet == nil {
		packet = report
	}
	d.reportFlow(p, sourceID, destID, context, mode, report, packet)
}

func (d *Datapath) reportExternalServiceFlowCommon(context *pucontext.PUContext, report *policy.FlowPolicy, packet *policy.FlowPolicy, app bool, p *packet.Packet, src, dst *collector.EndPoint) {

	record := &collector.FlowRecord{
		ContextID:   context.ID(),
		Source:      src,
		Destination: dst,
		DropReason:  collector.PolicyDrop,
		Action:      report.Action,
		Tags:        context.Annotations(),
		PolicyID:    report.PolicyID,
		L4Protocol:  p.IPProto,
	}

	if report.ObserveAction.Observed() {
		record.ObservedAction = packet.Action
		record.ObservedPolicyID = packet.PolicyID
	}

	d.collector.CollectFlowEvent(record)
}

func (d *Datapath) reportExternalServiceFlow(context *pucontext.PUContext, report *policy.FlowPolicy, packet *policy.FlowPolicy, app bool, p *packet.Packet) {

	var src, dst *collector.EndPoint

	srcID := report.ServiceID
	srcType := collector.EndPointTypeExternalIP
	dstID := context.ManagementID()
	dstType := collector.EnpointTypePU
	if app {
		srcID = context.ManagementID()
		srcType = collector.EnpointTypePU
		dstID = report.ServiceID
		dstType = collector.EndPointTypeExternalIP
	}

	src = collector.NewEndPoint(srcType, srcID, collector.OptionEndPointIPPort(p.SourceAddress.String(), p.SourcePort))
	dst = collector.NewEndPoint(dstType, dstID, collector.OptionEndPointIPPort(p.DestinationAddress.String(), p.DestinationPort))

	d.reportExternalServiceFlowCommon(context, report, packet, app, p, src, dst)
}

func (d *Datapath) reportReverseExternalServiceFlow(context *pucontext.PUContext, report *policy.FlowPolicy, packet *policy.FlowPolicy, app bool, p *packet.Packet) {

	var src, dst *collector.EndPoint

	srcID := report.ServiceID
	srcType := collector.EndPointTypeExternalIP
	dstID := context.ManagementID()
	dstType := collector.EnpointTypePU
	if app {
		srcID = context.ManagementID()
		srcType = collector.EnpointTypePU
		dstID = report.ServiceID
		dstType = collector.EndPointTypeExternalIP
	}

	src = collector.NewEndPoint(dstType, dstID, collector.OptionEndPointIPPort(p.DestinationAddress.String(), p.DestinationPort))
	dst = collector.NewEndPoint(srcType, srcID, collector.OptionEndPointIPPort(p.SourceAddress.String(), p.SourcePort))

	d.reportExternalServiceFlowCommon(context, report, packet, app, p, src, dst)
}
