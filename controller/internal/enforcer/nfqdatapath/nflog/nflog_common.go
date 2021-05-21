package nflog

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/counters"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cache"
	"go.uber.org/zap"
)

// NFLogger provides an interface for NFLog
type NFLogger interface {
	Run(ctx context.Context)
}

// GetPUContextFunc provides PU information given the id
type GetPUContextFunc func(hash string) (*pucontext.PUContext, error)

func recordCounters(protocol uint8, dstport uint16, srcport uint16, pu *pucontext.PUContext, puIsSource bool) {
	switch protocol {
	case packet.IPProtocolTCP:
		pu.Counters().IncrementCounter(counters.ErrDroppedTCPPackets)
	case packet.IPProtocolUDP:
		pu.Counters().IncrementCounter(counters.ErrDroppedUDPPackets)
		if puIsSource {
			switch dstport {
			case 53:
				pu.Counters().IncrementCounter(counters.ErrDroppedDNSPackets)
			case 67, 68:
				pu.Counters().IncrementCounter(counters.ErrDroppedDHCPPackets)
			case 123:
				pu.Counters().IncrementCounter(counters.ErrDroppedNTPPackets)
			}
		} else {
			switch srcport {
			case 53:
				pu.Counters().IncrementCounter(counters.ErrDroppedDNSPackets)
			case 67, 68:
				pu.Counters().IncrementCounter(counters.ErrDroppedDHCPPackets)
			case 123:
				pu.Counters().IncrementCounter(counters.ErrDroppedNTPPackets)
			}
		}

	case packet.IPProtocolICMP:
		pu.Counters().IncrementCounter(counters.ErrDroppedICMPPackets)

	}
}

func recordDroppedPacket(payload []byte, protocol uint8, srcIP, dstIP net.IP, srcPort, dstPort uint16, pu *pucontext.PUContext, puIsSource bool) (*collector.PacketReport, error) {

	report := &collector.PacketReport{}

	report.PUID = pu.ManagementID()
	report.Namespace = pu.ManagementNamespace()
	ipPacket, err := packet.New(packet.PacketTypeNetwork, payload, "", false)
	if err == nil {
		report.Length = int(ipPacket.GetIPLength())
		report.PacketID, _ = strconv.Atoi(ipPacket.ID())

	} else {
		zap.L().Debug("payload not valid", zap.Error(err))
		return nil, err
	}
	recordCounters(protocol, dstPort, srcPort, pu, puIsSource)
	if protocol == packet.IPProtocolTCP || protocol == packet.IPProtocolUDP {
		report.SourcePort = int(srcPort)
		report.DestinationPort = int(dstPort)
	}
	if protocol == packet.IPProtocolTCP {
		report.TCPFlags = int(ipPacket.GetTCPFlags())
	}
	report.Protocol = int(protocol)
	report.DestinationIP = dstIP.String()
	report.SourceIP = srcIP.String()
	report.TriremePacket = false
	report.DropReason = collector.PacketDrop

	if payload == nil {
		report.Payload = []byte{}
		return report, nil
	}
	if len(payload) <= 64 {
		report.Payload = make([]byte, len(payload))
		copy(report.Payload, payload)

	} else {
		report.Payload = make([]byte, 64)
		copy(report.Payload, payload[0:64])
	}

	return report, nil
}

func recordFromNFLogData(payload []byte, prefix string, protocol uint8, srcIP, dstIP net.IP, srcPort, dstPort uint16, getPUContext GetPUContextFunc, puIsSource bool) (*collector.FlowRecord, *collector.PacketReport, error) {

	var packetReport *collector.PacketReport
	var err error

	var hashID string
	var policyID string
	var extNetworkID string
	var ruleName string
	var encodedAction string

	parts := strings.Split(prefix, ":")
	switch len(parts) {
	case 4:
		// hashID:policyID:extNetworkID:action
		hashID, policyID, extNetworkID, encodedAction = parts[0], parts[1], parts[2], parts[3]
	case 5:
		// hashID:policyID:extNetworkID:ruleName:action
		hashID, policyID, extNetworkID, ruleName, encodedAction = parts[0], parts[1], parts[2], parts[3], parts[4]
	default:
		return nil, nil, fmt.Errorf("nflog: prefix doesn't contain sufficient information: %s", prefix)
	}

	pu, err := getPUContext(hashID)
	if err != nil {
		return nil, nil, err
	}

	// If we have a rule name, then look up the long version of logging prefix
	if len(ruleName) > 0 {
		realPrefix, ok := pu.LookupLogPrefix(policyID + ":" + extNetworkID + ":" + ruleName)
		if !ok {
			return nil, nil, fmt.Errorf("nflog: prefix not found in pucontext mapping: %s", prefix)
		}
		parts = strings.SplitN(realPrefix, ":", 3)
		if len(parts) != 3 {
			return nil, nil, fmt.Errorf("nflog: realPrefix doesn't contain sufficient information: %s", realPrefix)
		}
		policyID, extNetworkID, ruleName = parts[0], parts[1], parts[2]
	}

	if encodedAction == "10" {
		packetReport, err = recordDroppedPacket(payload, protocol, srcIP, dstIP, srcPort, dstPort, pu, puIsSource)
		return nil, packetReport, err
	}

	action, observedActionType, err := policy.EncodedStringToAction(encodedAction)
	if err != nil {
		return nil, packetReport, fmt.Errorf("nflog: unable to decode action for context id: %s (%s)", pu.ID(), encodedAction)
	}

	dropReason := ""
	if action.Rejected() {
		dropReason = collector.PolicyDrop
	}

	// point fix for now.
	var destination collector.EndPoint
	if protocol == packet.IPProtocolUDP || protocol == packet.IPProtocolTCP {
		destination = collector.EndPoint{
			IP:   dstIP.String(),
			Port: dstPort,
		}
	} else {
		destination = collector.EndPoint{
			IP: dstIP.String(),
		}
	}

	record := &collector.FlowRecord{
		ContextID: pu.ID(),
		Source: collector.EndPoint{
			IP: srcIP.String(),
		},
		Destination: destination,
		DropReason:  dropReason,
		PolicyID:    policyID,
		Tags:        pu.Annotations().GetSlice(),
		Action:      action | policy.Log, // Add the logging flag back
		L4Protocol:  protocol,
		Namespace:   pu.ManagementNamespace(),
		Count:       1,
		RuleName:    ruleName,
	}

	if action.Observed() {
		record.ObservedAction = action
		record.ObservedPolicyID = policyID
		record.ObservedActionType = observedActionType
	}

	if puIsSource {
		record.Source.Type = collector.EndPointTypePU
		record.Source.ID = pu.ManagementID()
		record.Destination.Type = collector.EndPointTypeExternalIP
		record.Destination.ID = extNetworkID
	} else {
		record.Source.Type = collector.EndPointTypeExternalIP
		record.Source.ID = extNetworkID
		record.Destination.Type = collector.EndPointTypePU
		record.Destination.ID = pu.ManagementID()
	}

	return record, packetReport, nil
}

func handleFlowReport(flowReportCache cache.DataStore, eventCollector collector.EventCollector, record *collector.FlowRecord, puIsSource bool) {

	if record == nil {
		return
	}

	uniqueKey := fmt.Sprintf("%d:%s:%d:%s:%d",
		record.L4Protocol, record.Source.IP, record.Source.Port, record.Destination.IP, record.Destination.Port)

	// If the flow record is ObserveContinue
	if record.ObservedActionType.ObserveContinue() {

		// If another observed continue policy is reported, then we ignore it.
		if _, err := flowReportCache.Get(uniqueKey); err == nil {
			return
		}

		// Add the observed policy report to the cache
		err := flowReportCache.Add(uniqueKey, record)
		if err != nil {
			eventCollector.CollectFlowEvent(record)
			zap.L().Error("handleFlowReport: unable to add flow record to cache", zap.Error(err))
		}
		return
	}

	// See if there was an ObserveContinue policy
	value, err := flowReportCache.Get(uniqueKey)
	if err == nil {
		report := value.(*collector.FlowRecord)
		record.ObservedAction = report.ObservedAction
		record.ObservedPolicyID = report.ObservedPolicyID
		record.ObservedActionType = report.ObservedActionType
		if puIsSource {
			record.Destination.ID = report.Destination.ID
			record.Destination.Type = report.Destination.Type
		} else {
			record.Source.ID = report.Source.ID
			record.Source.Type = report.Source.Type
		}
		err = flowReportCache.Remove(uniqueKey)
		if err != nil {
			zap.L().Error("handleFlowReport: failed to remove flow from cache", zap.Error(err))
		}
	}
	eventCollector.CollectFlowEvent(record)
}
