package nflog

// this code is a librarification the https://github.com/ncw/go-nflog-acctd

import (
	"strings"
	"sync"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/policy"

	"go.uber.org/zap"
)

const packetsQueueSize = 8

type puInfoFunc func(string) (string, *policy.TagStore)

type nfLogger struct {
	getPUInfo        puInfoFunc
	engineWg         sync.WaitGroup
	engineStop       chan struct{}
	processedPackets chan []Packet
	packetsToProcess chan []Packet
	nfloggers        []*nfLog
	ipv4groupSource  int
	ipv4groupDest    int
	ipv6groupSource  int
	ipv6groupDest    int
	collector        collector.EventCollector
}

// NewNFLogger returns a new NFLogger.
func NewNFLogger(ipv4groupSource, ipv4groupDest, ipv6groupSource, ipv6groupDest int, getPUInfo puInfoFunc, collector collector.EventCollector) NFLogger {

	logger := &nfLogger{
		engineStop:       make(chan struct{}),
		processedPackets: make(chan []Packet, packetsQueueSize),
		packetsToProcess: make(chan []Packet, packetsQueueSize),
		nfloggers:        []*nfLog{},
		ipv4groupSource:  ipv4groupSource,
		ipv4groupDest:    ipv4groupDest,
		ipv6groupSource:  ipv6groupSource,
		ipv6groupDest:    ipv6groupDest,
		getPUInfo:        getPUInfo,
		collector:        collector,
	}

	for i := 0; i < packetsQueueSize; i++ {
		logger.packetsToProcess <- make([]Packet, 0, 128)
	}

	return logger
}

// Start starts the NFlogger.
func (a *nfLogger) Start() {

	a.engineWg.Add(1)

	a.connectNFLogInstance(a.ipv4groupSource, 4, IPSource, 32)
	a.connectNFLogInstance(a.ipv4groupDest, 4, IPDest, 32)
	a.connectNFLogInstance(a.ipv6groupSource, 6, IPSource, 64)
	a.connectNFLogInstance(a.ipv6groupDest, 6, IPDest, 64)

	a.listen()
}

// Stop stops the NFlogger.
func (a *nfLogger) Stop() {

	for _, logger := range a.nfloggers {
		logger.stop()
	}

	close(a.engineStop)
	a.engineWg.Wait()
}

func (a *nfLogger) connectNFLogInstance(group int, ipType byte, direction IPDirection, prefixLen int) {
	if group == 0 {
		return
	}

	l, err := newNfLog(group, ipType, direction, prefixLen, a.packetsToProcess, a.processedPackets)
	if err != nil {
		zap.L().Error("nflog: unable to connect to nflog",
			zap.Int("group", group),
			zap.Bool("iptype", bool(direction)),
			zap.Int("prefix-length", prefixLen),
			zap.Error(err),
		)
		return
	}

	a.nfloggers = append(a.nfloggers, l)
	go l.start()
}

func (a *nfLogger) listen() {

	defer a.engineWg.Done()

	for {
		select {
		case ps := <-a.processedPackets:
			for _, p := range ps {

				parts := strings.SplitN(p.Prefix[:len(p.Prefix)-1], ":", 3)
				contextID, policyID, extSrvID := parts[0], parts[1], parts[2]
				shortAction := string(p.Prefix[len(p.Prefix)-1])

				puID, tags := a.getPUInfo(contextID)
				if puID == "" {
					zap.L().Error("nflog: unable to find pu ID associated given contexID", zap.String("contextID", contextID))
					continue
				}

				record := &collector.FlowRecord{
					ContextID: contextID,
					Source: &collector.EndPoint{
						IP: p.SourceAddr.String(),
					},
					Destination: &collector.EndPoint{
						IP:   p.DestinationAddr.String(),
						Port: uint16(p.DestinationPort),
					},
					PolicyID: policyID,
					Tags:     tags,
				}

				if shortAction == "a" {
					record.Action = "accept"
				} else {
					record.Action = "reject"
				}

				if p.Direction == IPSource {
					record.Source.Type = collector.Address
					record.Source.ID = extSrvID
					record.Destination.Type = collector.PU
					record.Destination.ID = puID
				} else {
					record.Source.Type = collector.PU
					record.Source.ID = puID
					record.Destination.Type = collector.Address
					record.Destination.ID = extSrvID
				}

				a.collector.CollectFlowEvent(record)
			}
			a.packetsToProcess <- ps

		case <-a.engineStop:
			return
		}
	}
}
