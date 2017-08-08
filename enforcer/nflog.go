// +build linux

package enforcer

import (
	"strings"
	"time"

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
}

func newNFLogger(ipv4groupSource, ipv4groupDest uint16, getPUInfo puInfoFunc, collector collector.EventCollector) nfLogger {

	return &nfLog{
		ipv4groupSource: ipv4groupSource,
		ipv4groupDest:   ipv4groupDest,
		collector:       collector,
		getPUInfo:       getPUInfo,
	}
}

// Start starts the NFlogger.
func (a *nfLog) start() {

	go nflog.BindAndListenForLogs([]uint16{a.ipv4groupSource}, 64, func(buf *nflog.NfPacket, data interface{}) {
		a.AddSrcLogs(buf)
	}, errorCallbacks)

	go nflog.BindAndListenForLogs([]uint16{a.ipv4groupDest}, 64, func(buf *nflog.NfPacket, data interface{}) {
		a.AddDstLogs(buf)
	}, errorCallbacks)

	time.Sleep(5 * time.Second)
}

func errorCallbacks(err error) {
	zap.L().Error("Error while processing packets", zap.Error(err))
}

func (a *nfLog) AddSrcLogs(buf *nflog.NfPacket) {
	parts := strings.SplitN(buf.Prefix[:len(buf.Prefix)-1], ":", 3)
	contextID, policyID, extSrvID := parts[0], parts[1], parts[2]
	shortAction := string(buf.Prefix[len(buf.Prefix)-1])

	puID, tags := a.getPUInfo(contextID)
	if puID == "" {
		zap.L().Error("nflog: unable to find pu ID associated given contexID", zap.String("contextID", contextID))
	}

	if buf.Protocol.String() == "TCP" {
		record := &collector.FlowRecord{
			ContextID: contextID,
			Source: &collector.EndPoint{
				IP: buf.SrcIP.String(),
			},
			Destination: &collector.EndPoint{
				IP:   buf.DstIP.String(),
				Port: uint16(buf.TCPDstPort),
			},
			PolicyID: policyID,
			Tags:     tags,
		}

		if shortAction == "a" {
			record.Action = policy.Accept
		} else {
			record.Action = policy.Reject
		}

		record.Source.Type = collector.Address
		record.Source.ID = extSrvID
		record.Destination.Type = collector.PU
		record.Destination.ID = puID

		a.collector.CollectFlowEvent(record)
	}

	if buf.Protocol.String() == "UDP" {
		record := &collector.FlowRecord{
			ContextID: contextID,
			Source: &collector.EndPoint{
				IP: buf.SrcIP.String(),
			},
			Destination: &collector.EndPoint{
				IP:   buf.DstIP.String(),
				Port: uint16(buf.UDPDstPort),
			},
			PolicyID: policyID,
			Tags:     tags,
		}

		if shortAction == "a" {
			record.Action = policy.Accept
		} else {
			record.Action = policy.Reject
		}

		record.Source.Type = collector.Address
		record.Source.ID = extSrvID
		record.Destination.Type = collector.PU
		record.Destination.ID = puID

		a.collector.CollectFlowEvent(record)
	}
}

func (a *nfLog) AddDstLogs(buf *nflog.NfPacket) {

	parts := strings.SplitN(buf.Prefix[:len(buf.Prefix)-1], ":", 3)
	contextID, policyID, extSrvID := parts[0], parts[1], parts[2]
	shortAction := string(buf.Prefix[len(buf.Prefix)-1])

	puID, tags := a.getPUInfo(contextID)
	if puID == "" {
		zap.L().Error("nflog: unable to find pu ID associated given contexID", zap.String("contextID", contextID))
	}

	if buf.Protocol.String() == "TCP" {
		record := &collector.FlowRecord{
			ContextID: contextID,
			Source: &collector.EndPoint{
				IP: buf.SrcIP.String(),
			},
			Destination: &collector.EndPoint{
				IP:   buf.DstIP.String(),
				Port: uint16(buf.TCPDstPort),
			},
			PolicyID: policyID,
			Tags:     tags,
		}

		if shortAction == "a" {
			record.Action = policy.Accept
		} else {
			record.Action = policy.Reject
		}

		record.Source.Type = collector.PU
		record.Source.ID = puID
		record.Destination.Type = collector.Address
		record.Destination.ID = extSrvID

		a.collector.CollectFlowEvent(record)
	}

	if buf.Protocol.String() == "UDP" {
		record := &collector.FlowRecord{
			ContextID: contextID,
			Source: &collector.EndPoint{
				IP: buf.SrcIP.String(),
			},
			Destination: &collector.EndPoint{
				IP:   buf.DstIP.String(),
				Port: uint16(buf.UDPDstPort),
			},
			PolicyID: policyID,
			Tags:     tags,
		}

		if shortAction == "a" {
			record.Action = policy.Accept
		} else {
			record.Action = policy.Reject
		}

		record.Source.Type = collector.PU
		record.Source.ID = puID
		record.Destination.Type = collector.Address
		record.Destination.ID = extSrvID

		a.collector.CollectFlowEvent(record)
	}

}
