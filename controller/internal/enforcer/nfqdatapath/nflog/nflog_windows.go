// +build windows

package nflog

import (
	"context"
	"fmt"
	"syscall"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/internal/windows/frontman"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.uber.org/zap"
)

// NfLogWindows has nflog data for windows
type NfLogWindows struct { //nolint:golint // ignore type name stutters
	getPUContext    GetPUContextFunc
	ipv4groupSource uint16
	ipv4groupDest   uint16
	collector       collector.EventCollector
}

// NewNFLogger provides an NFLog instance
func NewNFLogger(ipv4groupSource, ipv4groupDest uint16, getPUContext GetPUContextFunc, collector collector.EventCollector) NFLogger {
	return &NfLogWindows{
		ipv4groupSource: ipv4groupSource,
		ipv4groupDest:   ipv4groupDest,
		collector:       collector,
		getPUContext:    getPUContext,
	}
}

// Run does nothing for Windows
func (n *NfLogWindows) Run(ctx context.Context) {
}

// NfLogHandler handles log info from our Windows driver
func (n *NfLogWindows) NfLogHandler(logPacketInfo *frontman.LogPacketInfo, packetHeaderBytes []byte) error {
	var puIsSource bool
	switch uint16(logPacketInfo.GroupID) {
	case n.ipv4groupSource:
		puIsSource = false
	case n.ipv4groupDest:
		puIsSource = true
	default:
		return fmt.Errorf("unrecognized log group id: %d", logPacketInfo.GroupID)
	}

	ipPacket, err := packet.New(packet.PacketTypeNetwork, packetHeaderBytes, "", false)
	if err != nil {
		// failed to parse packet.
		// TODO(windows): handle it.
		zap.L().Debug("failed to parse rejected packet header: " + err.Error())
		return nil
	}

	record, packetEvent, err := recordFromNFLogData(packetHeaderBytes, syscall.UTF16ToString(logPacketInfo.LogPrefix[:]),
		ipPacket.IPProto(), ipPacket.SourceAddress(), ipPacket.DestinationAddress(), ipPacket.SourcePort(), ipPacket.DestPort(),
		n.getPUContext, puIsSource)
	if err != nil {
		return err
	}

	if record != nil {
		n.collector.CollectFlowEvent(record)
	}
	if packetEvent != nil {
		n.collector.CollectPacketEvent(packetEvent)
	}

	return nil
}
