package nfqdatapath

import (
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

func (d *Datapath) reportAcceptedFlow(p *packet.Packet, conn *connection.TCPConnection, sourceID string, destID string, context *pucontext.PUContext, report *policy.FlowPolicy, packet *policy.FlowPolicy, reverse bool) { // nolint:unparam

	if sourceID == destID {
		report = &policy.FlowPolicy{
			Action:   policy.Accept | policy.Log,
			PolicyID: "local",
		}
		packet = report
	}

	sourceController, destinationController := getTCPConnectionInfo(conn)

	src, dst := d.generateEndpoints(p, sourceID, destID, reverse)

	d.reportFlow(p, src, dst, context, "", report, packet, sourceController, destinationController)
}

func (d *Datapath) reportRejectedFlow(p *packet.Packet, conn *connection.TCPConnection, sourceID string, destID string, context *pucontext.PUContext, mode string, report *policy.FlowPolicy, packet *policy.FlowPolicy, reverse bool) { // nolint:unparam

	if report == nil {
		report = &policy.FlowPolicy{
			Action:   policy.Reject | policy.Log,
			PolicyID: "default",
		}
	}
	if packet == nil {
		packet = report
	}

	sourceController, destinationController := getTCPConnectionInfo(conn)

	src, dst := d.generateEndpoints(p, sourceID, destID, reverse)

	d.reportFlow(p, src, dst, context, mode, report, packet, sourceController, destinationController)
}

func (d *Datapath) reportUDPAcceptedFlow(p *packet.Packet, conn *connection.UDPConnection, sourceID string, destID string, context *pucontext.PUContext, report *policy.FlowPolicy, packet *policy.FlowPolicy, reverse bool) { // nolint:unparam

	sourceController, destinationController := getUDPConnectionInfo(conn)

	src, dst := d.generateEndpoints(p, sourceID, destID, reverse)

	d.reportFlow(p, src, dst, context, "", report, packet, sourceController, destinationController)
}

func (d *Datapath) reportUDPRejectedFlow(p *packet.Packet, conn *connection.UDPConnection, sourceID string, destID string, context *pucontext.PUContext, mode string, report *policy.FlowPolicy, packet *policy.FlowPolicy, reverse bool) { // nolint:unparam
	if report == nil {
		report = &policy.FlowPolicy{
			Action:   policy.Reject | policy.Log,
			PolicyID: "default",
		}
	}
	if packet == nil {
		packet = report
	}

	sourceController, destinationController := getUDPConnectionInfo(conn)

	src, dst := d.generateEndpoints(p, sourceID, destID, reverse)
	d.reportFlow(p, src, dst, context, mode, report, packet, sourceController, destinationController)
}

func (d *Datapath) reportExternalServiceFlowCommon(context *pucontext.PUContext, report *policy.FlowPolicy, actual *policy.FlowPolicy, app bool, p *packet.Packet, src, dst *collector.EndPoint) {
	if app {
		// If you have an observe policy then its external network gets reported as the dest or src ID.
		// Really we should has an oSrc and oDest ID but currently we don't.
		src.ID = context.ManagementID()
		src.Type = collector.EndPointTypePU
		dst.ID = report.ServiceID
		dst.Type = collector.EndPointTypeExternalIP
	} else {
		src.ID = report.ServiceID
		src.Type = collector.EndPointTypeExternalIP
		dst.ID = context.ManagementID()
		dst.Type = collector.EndPointTypePU
	}

	dropReason := ""
	if report.Action.Rejected() || actual.Action.Rejected() {
		dropReason = collector.PolicyDrop
	}

	record := &collector.FlowRecord{
		ContextID:   context.ID(),
		Source:      *src,
		Destination: *dst,
		DropReason:  dropReason,
		Action:      actual.Action,
		PolicyID:    actual.PolicyID,
		L4Protocol:  p.IPProto(),
		Namespace:   context.ManagementNamespace(),
		Count:       1,
		RuleName:    actual.RuleName,
	}

	if context.Annotations() != nil {
		record.Tags = context.Annotations().GetSlice()
	}

	if report.ObserveAction.Observed() {
		record.ObservedAction = report.Action
		record.ObservedPolicyID = report.PolicyID
		record.ObservedActionType = report.ObserveAction
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
		Type: collector.EndPointTypePU,
	}

	dst := &collector.EndPoint{
		ID:   destID,
		IP:   p.DestinationAddress().String(),
		Port: p.DestPort(),
		Type: collector.EndPointTypePU,
	}

	if src.ID == collector.DefaultEndPoint {
		src.Type = collector.EndPointTypeExternalIP
	}
	if dst.ID == collector.DefaultEndPoint {
		dst.Type = collector.EndPointTypeExternalIP
	}

	if reverse {
		return dst, src
	}

	return src, dst
}

func getTCPConnectionInfo(conn *connection.TCPConnection) (string, string) {
	sourceController, destinationController := "", ""
	if conn != nil {
		sourceController, destinationController = conn.SourceController, conn.DestinationController
	}
	return sourceController, destinationController
}

func getUDPConnectionInfo(conn *connection.UDPConnection) (string, string) {
	sourceController, destinationController := "", ""
	if conn != nil {
		sourceController, destinationController = conn.SourceController, conn.DestinationController
	}
	return sourceController, destinationController
}
