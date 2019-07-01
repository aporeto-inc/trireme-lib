// +build linux

package nflog

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"go.aporeto.io/netlink-go/nflog"
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

type nfLog struct {
	getPUInfo       GetPUInfoFunc
	ipv4groupSource uint16
	ipv4groupDest   uint16
	collector       collector.EventCollector
	srcNflogHandle  nflog.NFLog
	dstNflogHandle  nflog.NFLog
	sync.Mutex
}

// NewNFLogger provides an NFLog instance
func NewNFLogger(ipv4groupSource, ipv4groupDest uint16, getPUInfo GetPUInfoFunc, collector collector.EventCollector) NFLogger {

	return &nfLog{
		ipv4groupSource: ipv4groupSource,
		ipv4groupDest:   ipv4groupDest,
		collector:       collector,
		getPUInfo:       getPUInfo,
	}
}

// Run runs the Nf Logger
func (a *nfLog) Run(ctx context.Context) {
	a.Lock()
	a.srcNflogHandle, _ = nflog.BindAndListenForLogs([]uint16{a.ipv4groupSource}, 64, a.sourceNFLogsHanlder, a.nflogErrorHandler)
	a.dstNflogHandle, _ = nflog.BindAndListenForLogs([]uint16{a.ipv4groupDest}, 64, a.destNFLogsHandler, a.nflogErrorHandler)
	a.Unlock()

	go func() {
		<-ctx.Done()
		a.Lock()
		a.srcNflogHandle.NFlogClose()
		a.dstNflogHandle.NFlogClose()
		a.Unlock()

	}()
}

func (a *nfLog) sourceNFLogsHanlder(buf *nflog.NfPacket, _ interface{}) {

	record, packetEvent, err := a.recordFromNFLogBuffer(buf, false)
	if err != nil {
		zap.L().Error("sourceNFLogsHanlder: create flow record", zap.Error(err))
		return
	}
	if record != nil {
		a.collector.CollectFlowEvent(record)
	}
	if packetEvent != nil {
		a.collector.CollectPacketEvent(packetEvent)
	}
}

func (a *nfLog) destNFLogsHandler(buf *nflog.NfPacket, _ interface{}) {

	record, packetEvent, err := a.recordFromNFLogBuffer(buf, true)
	if err != nil {
		zap.L().Error("destNFLogsHandler: create flow record", zap.Error(err))
		return
	}
	if record != nil {
		a.collector.CollectFlowEvent(record)
	}
	if packetEvent != nil {
		a.collector.CollectPacketEvent(packetEvent)
	}

}

func (a *nfLog) nflogErrorHandler(err error) {

	zap.L().Error("Error while processing nflog packet", zap.Error(err))
}

func (a *nfLog) recordDroppedPacket(buf *nflog.NfPacket) (*collector.PacketReport, error) {
	report := &collector.PacketReport{
		Payload: make([]byte, 64),
	}
	parts := strings.SplitN(buf.Prefix[:len(buf.Prefix)-1], ":", 3)

	if len(parts) != 3 {
		return nil, fmt.Errorf("nflog: prefix doesn't contain sufficient information: %s", buf.Prefix)
	}

	contextID, _, _ := parts[0], parts[1], parts[2]
	puID, namespace, _ := a.getPUInfo(contextID)
	if puID == "" {
		return nil, fmt.Errorf("nflog: unable to find pu id associated given context id: %s", contextID)
	}

	report.PUID = puID
	report.Namespace = namespace
	ipPacket, err := packet.New(packet.PacketTypeNetwork, buf.Payload, "", false)
	if err == nil {
		report.Length = int(ipPacket.GetIPLength())
		report.PacketID, _ = strconv.Atoi(ipPacket.ID())

	} else {
		zap.L().Debug("Payload Not Valid", zap.Error(err))
	}

	if buf.Protocol == packet.IPProtocolTCP || buf.Protocol == packet.IPProtocolUDP {
		report.SourcePort = int(buf.Ports.SrcPort)
		report.DestinationPort = int(buf.Ports.DstPort)
	}
	if buf.Protocol == packet.IPProtocolTCP {
		report.TCPFlags = int(ipPacket.GetTCPFlags())
	}
	report.DestinationIP = buf.DstIP.String()
	report.SourceIP = buf.SrcIP.String()
	report.TriremePacket = false
	report.DropReason = collector.PacketDrop
	copy(report.Payload, buf.Payload[0:64])
	return report, nil
}
func (a *nfLog) recordFromNFLogBuffer(buf *nflog.NfPacket, puIsSource bool) (*collector.FlowRecord, *collector.PacketReport, error) {

	parts := strings.SplitN(buf.Prefix[:len(buf.Prefix)-1], ":", 3)

	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("nflog: prefix doesn't contain sufficient information: %s", buf.Prefix)
	}

	contextID, policyID, extSrvID := parts[0], parts[1], parts[2]
	encodedAction := string(buf.Prefix[len(buf.Prefix)-1])

	if encodedAction == "10" {
		zap.L().Error("Debug RecordDropped packet")
		packetReport, err := a.recordDroppedPacket(buf)
		return nil, packetReport, err
	}

	puID, puNamespace, tags := a.getPUInfo(contextID)

	if puID == "" {
		return nil, nil, fmt.Errorf("nflog: unable to find pu id associated given context id: %s", contextID)
	}

	action, _, err := policy.EncodedStringToAction(encodedAction)
	if err != nil {
		return nil, nil, fmt.Errorf("nflog: unable to decode action for context id: %s (%s)", contextID, encodedAction)
	}

	dropReason := ""
	if action.Rejected() {
		dropReason = collector.PolicyDrop
	}

	// point fix for now.
	var destination *collector.EndPoint
	if buf.Protocol == packet.IPProtocolUDP || buf.Protocol == packet.IPProtocolTCP {
		destination = &collector.EndPoint{
			IP:   buf.DstIP.String(),
			Port: buf.DstPort,
		}
	} else {
		destination = &collector.EndPoint{
			IP: buf.DstIP.String(),
		}
	}

	record := &collector.FlowRecord{
		ContextID: contextID,
		Source: &collector.EndPoint{
			IP: buf.SrcIP.String(),
		},
		Destination: destination,
		DropReason:  dropReason,
		PolicyID:    policyID,
		Tags:        tags,
		Action:      action,
		L4Protocol:  buf.Protocol,
		Namespace:   puNamespace,
		Count:       1,
	}

	if action.Observed() {
		record.ObservedAction = action
		record.ObservedPolicyID = policyID
	}

	if puIsSource {
		record.Source.Type = collector.EnpointTypePU
		record.Source.ID = puID
		record.Destination.Type = collector.EndPointTypeExternalIP
		record.Destination.ID = extSrvID
	} else {
		record.Source.Type = collector.EndPointTypeExternalIP
		record.Source.ID = extSrvID
		record.Destination.Type = collector.EnpointTypePU
		record.Destination.ID = puID
	}

	return record, nil, nil
}
