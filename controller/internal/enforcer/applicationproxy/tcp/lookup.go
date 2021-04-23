package tcp

import (
	"fmt"
	"net"
	"strconv"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.uber.org/zap"
)

const indeterminateRemoteController = ""

// proxyFlowProperties is a struct used to pass flow information up
type proxyFlowProperties struct {
	myControllerID string
	SourceIP       string
	DestIP         string
	PolicyID       string
	ServiceID      string
	DestType       collector.EndPointType
	SourceType     collector.EndPointType
	SourcePort     uint16
	DestPort       uint16
}

type lookup struct {
	SourceIP   net.IP
	DestIP     net.IP
	SourcePort uint16
	DestPort   uint16
	collector  collector.EventCollector
	puContext  *pucontext.PUContext
	pfp        *proxyFlowProperties
	client     bool
}

// IDLookup performs policy lookup based on incoming tags from remote PU and matching against our policy DB.
// Stats reporting is done for:
//   - all rejects
//   - accepts on server
func (l *lookup) IDLookup(remoteController, remotePUID string, tags *policy.TagStore) bool { // nolint: staticcheck

	remoteController = ""
	// TODO: Enable this
	// if remoteController == l.pfp.myControllerID {
	// 	remoteController = ""
	// }

	report, packet := l.Policy(tags)

	if packet.Action.Rejected() {
		l.ReportStats(
			collector.EndPointTypePU,
			remoteController,
			remotePUID,
			collector.PolicyDrop,
			report,
			packet,
			false,
		)
		zap.L().Debug("lookup reject", zap.Bool("client", l.client), zap.Strings("tags", tags.GetSlice()))
		return false
	}

	if !l.client && packet.Action.Accepted() {
		l.ReportStats(
			collector.EndPointTypePU,
			remoteController,
			remotePUID,
			"N/A",
			report,
			packet,
			false,
		)
		zap.L().Debug("lookup accept", zap.Bool("client", l.client), zap.Strings("tags", tags.GetSlice()))
	}
	return true
}

// Policy performs policy lookup based on incoming tags from remote PU and matching against our policy DB.
// It also returns the report and packet policy.
func (l *lookup) Policy(tags *policy.TagStore) (*policy.FlowPolicy, *policy.FlowPolicy) {

	var report *policy.FlowPolicy
	var packet *policy.FlowPolicy

	if l.client {
		tags.AppendKeyValue(constants.PortNumberLabelString, fmt.Sprintf("%s/%s", constants.TCPProtoString, strconv.Itoa(int(l.DestPort))))
		report, packet = l.puContext.SearchTxtRules(tags, false)
	} else {
		tags.AppendKeyValue(constants.PortNumberLabelString, fmt.Sprintf("%s/%s", constants.TCPProtoString, strconv.Itoa(int(l.DestPort))))
		report, packet = l.puContext.SearchRcvRules(tags)
	}

	return report, packet
}

func (l *lookup) IPLookup() bool {

	var report *policy.FlowPolicy
	var packetPolicy *policy.FlowPolicy
	var noPolicy error

	if l.client {
		report, packetPolicy, noPolicy = l.puContext.ApplicationACLPolicyFromAddr(l.DestIP, l.DestPort, packet.IPProtocolTCP)
	} else {
		report, packetPolicy, noPolicy = l.puContext.NetworkACLPolicyFromAddr(l.SourceIP, l.DestPort, packet.IPProtocolTCP)
	}

	matchString := "none"
	if noPolicy != nil {
		matchString = noPolicy.Error()
	}

	// Clients and Servers should reject and report if a reject action is found.
	if packetPolicy.Action.Rejected() {

		l.ReportStats(
			collector.EndPointTypeExternalIP,
			indeterminateRemoteController,
			packetPolicy.ServiceID,
			collector.PolicyDrop,
			report,
			packetPolicy,
			false,
		)
		zap.L().Debug(
			"IP ACL Lookup Reject",
			zap.Bool("client", l.client),
			zap.String("match", matchString),
			zap.String("src-ip", l.pfp.SourceIP),
			zap.Uint16("src-port", l.SourcePort),
			zap.String("dst-ip", l.pfp.DestIP),
			zap.Uint16("dst-port", l.DestPort),
			zap.String("report", report.PolicyID),
			zap.String("policy", packetPolicy.PolicyID))
		return false
	}

	if !l.client && packetPolicy.Action.Accepted() {
		l.ReportStats(
			collector.EndPointTypeExternalIP,
			indeterminateRemoteController,
			packetPolicy.ServiceID,
			"N/A",
			report,
			packetPolicy,
			false,
		)
	}
	zap.L().Debug(
		"IP ACL Lookup Accept",
		zap.Bool("client", l.client),
		zap.String("match", matchString),
		zap.String("src-ip", l.pfp.SourceIP),
		zap.Uint16("src-port", l.SourcePort),
		zap.String("dst-ip", l.pfp.DestIP),
		zap.Uint16("dst-port", l.DestPort),
		zap.String("report", report.PolicyID),
		zap.String("policy", packetPolicy.PolicyID))
	return true
}

func (l *lookup) ReportStats(remoteType collector.EndPointType, remoteController string, remotePUID string, mode string, report *policy.FlowPolicy, packet *policy.FlowPolicy, accept bool) {

	dstController, dstID, srcController, srcID := "", "", "", ""

	if l.client {
		l.pfp.DestType = remoteType
		if l.pfp.myControllerID != remoteController {
			dstController = remoteController
		}
		dstID = remotePUID
		srcID = l.puContext.ManagementID()
	} else {
		l.pfp.SourceType = remoteType
		dstID = l.puContext.ManagementID()
		if l.pfp.myControllerID != remoteController {
			srcController = remoteController
		}
		srcID = remotePUID
	}

	if accept {
		l.reportAcceptedFlow(
			l.pfp,
			srcID,
			dstID,
			l.puContext,
			report,
			packet,
			srcController,
			dstController,
		)
		return
	}

	l.reportRejectedFlow(
		l.pfp,
		srcID,
		dstID,
		l.puContext,
		mode,
		report,
		packet,
		srcController,
		dstController,
	)
}

func (l *lookup) reportFlow(flowproperties *proxyFlowProperties, sourceID string, destID string, context *pucontext.PUContext, mode string, report *policy.FlowPolicy, actual *policy.FlowPolicy, sourceController string, destController string) {

	c := &collector.FlowRecord{
		ContextID: context.ID(),
		Source: collector.EndPoint{
			ID:   sourceID,
			IP:   flowproperties.SourceIP,
			Port: flowproperties.SourcePort,
			Type: flowproperties.SourceType,
		},
		Destination: collector.EndPoint{
			ID:   destID,
			IP:   flowproperties.DestIP,
			Port: flowproperties.DestPort,
			Type: flowproperties.DestType,
		},

		Action:                actual.Action,
		DropReason:            mode,
		PolicyID:              actual.PolicyID,
		L4Protocol:            packet.IPProtocolTCP,
		ServiceType:           policy.ServiceTCP,
		ServiceID:             flowproperties.ServiceID,
		Namespace:             context.ManagementNamespace(),
		SourceController:      sourceController,
		DestinationController: destController,
	}

	if context.Annotations() != nil {
		c.Tags = context.Annotations().GetSlice()
	}

	if report.ObserveAction.Observed() {
		c.ObservedAction = report.Action
		c.ObservedPolicyID = report.PolicyID
		c.ObservedActionType = report.ObserveAction
	}

	l.collector.CollectFlowEvent(c)
}

func (l *lookup) reportAcceptedFlow(flowproperties *proxyFlowProperties, sourceID string, destID string, context *pucontext.PUContext, report *policy.FlowPolicy, packet *policy.FlowPolicy, sourceController string, destController string) {

	l.reportFlow(flowproperties, sourceID, destID, context, "N/A", report, packet, sourceController, destController)
}

func (l *lookup) reportRejectedFlow(flowproperties *proxyFlowProperties, sourceID string, destID string, context *pucontext.PUContext, mode string, report *policy.FlowPolicy, packet *policy.FlowPolicy, sourceController string, destController string) {

	if report == nil {
		report = &policy.FlowPolicy{
			Action:   policy.Reject | policy.Log,
			PolicyID: "default",
		}
	}
	if packet == nil {
		packet = report
	}
	l.reportFlow(flowproperties, sourceID, destID, context, mode, report, packet, sourceController, destController)
}
