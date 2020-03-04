package nflog

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/policy"
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
		pu.IncrementCounters(pucontext.ErrDroppedTCPPackets)
	case packet.IPProtocolUDP:
		pu.IncrementCounters(pucontext.ErrDroppedUDPPackets)
		if puIsSource {
			switch dstport {
			case 53:
				pu.IncrementCounters(pucontext.ErrDroppedDNSPackets)
			case 67, 68:
				pu.IncrementCounters(pucontext.ErrDroppedDHCPPackets)
			case 123:
				pu.IncrementCounters(pucontext.ErrDroppedNTPPackets)
			}
		} else {
			switch srcport {
			case 53:
				pu.IncrementCounters(pucontext.ErrDroppedDNSPackets)
			case 67, 68:
				pu.IncrementCounters(pucontext.ErrDroppedDHCPPackets)
			case 123:
				pu.IncrementCounters(pucontext.ErrDroppedNTPPackets)
			}
		}

	case packet.IPProtocolICMP:
		pu.IncrementCounters(pucontext.ErrDroppedICMPPackets)

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
	report.DropReason = "packetdrop"

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

	// `hashID:policyID:extServiceID:action`
	parts := strings.SplitN(prefix, ":", 4)
	if len(parts) != 4 {
		return nil, nil, fmt.Errorf("nflog: prefix doesn't contain sufficient information: %s", prefix)
	}
	hashID, policyID, extServiceID, encodedAction := parts[0], parts[1], parts[2], parts[3]

	pu, err := getPUContext(hashID)
	if err != nil {
		return nil, nil, err
	}

	if encodedAction == "10" {
		packetReport, err = recordDroppedPacket(payload, protocol, srcIP, dstIP, srcPort, dstPort, pu, puIsSource)
		return nil, packetReport, err
	}

	action, _, err := policy.EncodedStringToAction(encodedAction)
	if err != nil {
		return nil, packetReport, fmt.Errorf("nflog: unable to decode action for context id: %s (%s)", pu.ID(), encodedAction)
	}

	dropReason := collector.None
	if action.Rejected() {
		dropReason = collector.PolicyDrop
	}

	// point fix for now.
	var destination *collector.EndPoint
	if protocol == packet.IPProtocolUDP || protocol == packet.IPProtocolTCP {
		destination = &collector.EndPoint{
			IP:   dstIP.String(),
			Port: dstPort,
		}
	} else {
		destination = &collector.EndPoint{
			IP: dstIP.String(),
		}
	}

	record := &collector.FlowRecord{
		ContextID: pu.ID(),
		Source: &collector.EndPoint{
			IP: srcIP.String(),
		},
		Destination: destination,
		DropReason:  dropReason,
		PolicyID:    policyID,
		Tags:        pu.Annotations().Copy(),
		Action:      action,
		L4Protocol:  protocol,
		Namespace:   pu.ManagementNamespace(),
		Count:       1,
	}

	if action.Observed() {
		record.ObservedAction = action
		record.ObservedPolicyID = policyID
	}

	if puIsSource {
		record.Source.Type = collector.EnpointTypePU
		record.Source.ID = pu.ManagementID()
		record.Destination.Type = collector.EndPointTypeExternalIP
		record.Destination.ID = extServiceID
	} else {
		record.Source.Type = collector.EndPointTypeExternalIP
		record.Source.ID = extServiceID
		record.Destination.Type = collector.EnpointTypePU
		record.Destination.ID = pu.ManagementID()
	}

	return record, packetReport, nil
}
