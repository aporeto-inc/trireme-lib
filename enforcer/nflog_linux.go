// +build linux

package enforcer

import (
	"fmt"
	"strings"

	"github.com/aporeto-inc/netlink-go/nflog"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/policy"

	"go.uber.org/zap"
)

type nfLog struct {
	getPUInfo       puInfoFunc
	ipv4groupSource uint16
	ipv4groupDest   uint16
	collector       collector.EventCollector
	srcNflogHandle  nflog.NFLog
	dstNflogHandle  nflog.NFLog
}

func newNFLogger(ipv4groupSource, ipv4groupDest uint16, getPUInfo puInfoFunc, collector collector.EventCollector) nfLogger {

	return &nfLog{
		ipv4groupSource: ipv4groupSource,
		ipv4groupDest:   ipv4groupDest,
		collector:       collector,
		getPUInfo:       getPUInfo,
	}
}

func (a *nfLog) start() {

	a.srcNflogHandle, _ = nflog.BindAndListenForLogs([]uint16{a.ipv4groupSource}, 64, a.sourceNFLogsHanlder, a.nflogErrorHandler)
	a.dstNflogHandle, _ = nflog.BindAndListenForLogs([]uint16{a.ipv4groupDest}, 64, a.destNFLogsHandler, a.nflogErrorHandler)

}

func (a *nfLog) stop() {
	a.srcNflogHandle.NFlogClose()
	a.dstNflogHandle.NFlogClose()
}

func (a *nfLog) sourceNFLogsHanlder(buf *nflog.NfPacket, data interface{}) {

	record, err := a.recordFromNFLogBuffer(buf, false)
	if err != nil {
		zap.L().Error("sourceNFLogsHanlder: create flow record", zap.Error(err))
		return
	}

	a.collector.CollectFlowEvent(record)
}

func (a *nfLog) destNFLogsHandler(buf *nflog.NfPacket, data interface{}) {

	record, err := a.recordFromNFLogBuffer(buf, true)
	if err != nil {
		zap.L().Error("destNFLogsHandler: create flow record", zap.Error(err))
		return
	}

	a.collector.CollectFlowEvent(record)
}

func (a *nfLog) nflogErrorHandler(err error) {

	zap.L().Error("Error while processing nflog packet", zap.Error(err))
}

func (a *nfLog) recordFromNFLogBuffer(buf *nflog.NfPacket, puIsSource bool) (*collector.FlowRecord, error) {

	parts := strings.SplitN(buf.Prefix[:len(buf.Prefix)-1], ":", 3)

	if len(parts) != 3 {
		return nil, fmt.Errorf("nflog: prefix doesn't contain sufficient information: %s", buf.Prefix)
	}

	contextID, policyID, extSrvID := parts[0], parts[1], parts[2]
	shortAction := string(buf.Prefix[len(buf.Prefix)-1])

	puID, tags := a.getPUInfo(contextID)
	if puID == "" {
		return nil, fmt.Errorf("nflog: unable to find pu ID associated given contexID: %s", contextID)
	}

	var action policy.ActionType
	if shortAction == "a" {
		action = policy.Accept
	} else {
		action = policy.Reject
	}

	record := &collector.FlowRecord{
		ContextID: contextID,
		Source: &collector.EndPoint{
			IP: buf.SrcIP.String(),
		},
		Destination: &collector.EndPoint{
			IP:   buf.DstIP.String(),
			Port: uint16(buf.DstPort),
		},
		PolicyID: policyID,
		Tags:     tags,
		Action:   action,
	}

	if puIsSource {
		record.Source.Type = collector.PU
		record.Source.ID = puID
		record.Destination.Type = collector.Address
		record.Destination.ID = extSrvID
	} else {
		record.Source.Type = collector.Address
		record.Source.ID = extSrvID
		record.Destination.Type = collector.PU
		record.Destination.ID = puID
	}

	return record, nil
}
