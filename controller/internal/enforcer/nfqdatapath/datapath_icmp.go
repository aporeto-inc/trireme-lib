// +build linux

package nfqdatapath

import (
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
)

type icmpActionType int

const (
	icmpAccept icmpActionType = iota
	icmpDrop
)

func (d *Datapath) processNetworkICMPPacket(context *pucontext.PUContext, packet *packet.Packet, icmpType int8, icmpCode int8) icmpActionType {

	srcAddr := packet.SourceAddress()
	dstAddr := packet.DestinationAddress()

	report, pkt, err := context.NetworkICMPACLPolicy(srcAddr, icmpType, icmpCode)

	d.reportExternalServiceFlowCommon(context, report, pkt, false, packet, &collector.EndPoint{IP: srcAddr.String()}, &collector.EndPoint{IP: dstAddr.String()})
	if err != nil || pkt.Action.Rejected() {
		return icmpDrop
	}

	return icmpAccept
}

func (d *Datapath) processApplicationICMPPacket(context *pucontext.PUContext, packet *packet.Packet, icmpType int8, icmpCode int8) icmpActionType {

	srcAddr := packet.SourceAddress()
	dstAddr := packet.DestinationAddress()

	report, pkt, err := context.ApplicationICMPACLPolicy(dstAddr, icmpType, icmpCode)

	d.reportExternalServiceFlowCommon(context, report, pkt, true, packet, &collector.EndPoint{IP: srcAddr.String()}, &collector.EndPoint{IP: dstAddr.String()})

	if err != nil || pkt.Action.Rejected() {
		return icmpDrop
	}

	return icmpAccept
}
