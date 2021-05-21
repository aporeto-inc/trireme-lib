// +build linux

package nflog

import (
	"context"
	"sync"
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/counters"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cache"
	"go.aporeto.io/netlink-go/nflog"
	"go.uber.org/zap"
)

type nfLog struct {
	getPUContext    GetPUContextFunc
	ipv4groupSource uint16
	ipv4groupDest   uint16
	collector       collector.EventCollector
	srcNflogHandle  nflog.NFLog
	dstNflogHandle  nflog.NFLog
	flowReportCache cache.DataStore
	sync.Mutex
}

// NewNFLogger provides an NFLog instance
func NewNFLogger(ipv4groupSource, ipv4groupDest uint16, getPUContext GetPUContextFunc, collector collector.EventCollector) NFLogger {
	nfLog := &nfLog{
		ipv4groupSource: ipv4groupSource,
		ipv4groupDest:   ipv4groupDest,
		collector:       collector,
		getPUContext:    getPUContext,
	}
	nfLog.flowReportCache = cache.NewCacheWithExpirationNotifier("flowReportCache", time.Second*5, nfLog.logExpirationNotifier)
	return nfLog
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

	handleFlowReport(a.flowReportCache, a.collector, record, false)

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

	handleFlowReport(a.flowReportCache, a.collector, record, true)

	if packetEvent != nil {
		a.collector.CollectPacketEvent(packetEvent)
	}
}

func (a *nfLog) nflogErrorHandler(err error) {
	counters.IncrementCounter(counters.ErrNfLogError)
	zap.L().Debug("Error while processing nflog packet", zap.Error(err))
}

func (a *nfLog) recordFromNFLogBuffer(buf *nflog.NfPacket, puIsSource bool) (*collector.FlowRecord, *collector.PacketReport, error) {
	return recordFromNFLogData(buf.Payload, buf.Prefix, buf.Protocol, buf.SrcIP, buf.DstIP, buf.SrcPort, buf.DstPort, a.getPUContext, puIsSource)
}

func (a *nfLog) logExpirationNotifier(_ interface{}, item interface{}) {
	if item != nil {
		// Basically we had an observed flow report that didn't get reported yet.
		record := item.(*collector.FlowRecord)
		a.collector.CollectFlowEvent(record)
	}
}
