// +build windows

package nflog

import (
	"context"
	"fmt"
	"syscall"
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/counters"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cache"
	"go.aporeto.io/enforcerd/trireme-lib/utils/frontman"
	"go.uber.org/zap"
)

// NfLogWindows has nflog data for windows
type NfLogWindows struct { // nolint:golint // ignore type name stutters
	getPUContext    GetPUContextFunc
	ipv4groupSource uint16
	ipv4groupDest   uint16
	collector       collector.EventCollector
	flowReportCache cache.DataStore
}

// NewNFLogger provides an NFLog instance
func NewNFLogger(ipv4groupSource, ipv4groupDest uint16, getPUContext GetPUContextFunc, collector collector.EventCollector) NFLogger {
	nfLog := &NfLogWindows{
		ipv4groupSource: ipv4groupSource,
		ipv4groupDest:   ipv4groupDest,
		collector:       collector,
		getPUContext:    getPUContext,
	}
	nfLog.flowReportCache = cache.NewCacheWithExpirationNotifier("flowReportCache", time.Second*5, nfLog.logExpirationNotifier)
	return nfLog
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
		counters.IncrementCounter(counters.ErrNfLogError)
		zap.L().Debug("Error while processing nflog packet", zap.Error(err))
		return nil
	}

	record, packetEvent, err := recordFromNFLogData(packetHeaderBytes, syscall.UTF16ToString(logPacketInfo.LogPrefix[:]),
		ipPacket.IPProto(), ipPacket.SourceAddress(), ipPacket.DestinationAddress(), ipPacket.SourcePort(), ipPacket.DestPort(),
		n.getPUContext, puIsSource)
	if err != nil {
		return err
	}

	if record != nil {
		handleFlowReport(n.flowReportCache, n.collector, record, puIsSource)
	}
	if packetEvent != nil {
		n.collector.CollectPacketEvent(packetEvent)
	}

	return nil
}

func (n *NfLogWindows) logExpirationNotifier(_ interface{}, item interface{}) {
	if item != nil {
		// Basically we had an observed flow report that didn't get reported yet.
		record := item.(*collector.FlowRecord)
		n.collector.CollectFlowEvent(record)
	}
}
