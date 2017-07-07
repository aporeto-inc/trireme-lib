package nflog

// this code is a librarification the https://github.com/ncw/go-nflog-acctd

import (
	"fmt"
	"strings"
	"sync"

	"github.com/aporeto-inc/trireme/collector"

	"go.uber.org/zap"
)

const (
	// PacketsQueueSize TODO
	PacketsQueueSize = 8
)

// Globals
var (
	Version        = "0.1"
	DefaultMapSize = 1024
)

type nfLogger struct {
	engineWg         sync.WaitGroup
	engineStop       chan struct{}
	processedPackets chan []Packet
	packetsToProcess chan []Packet
	nfloggers        []*nfLog
	ipv4groupSource  int
	ipv4groupDest    int
	ipv6groupSource  int
	ipv6groupDest    int
}

// NewNFLogger returns a new NFLogger.
func NewNFLogger(ipv4groupSource, ipv4groupDest, ipv6groupSource, ipv6groupDest int) NFLogger {

	logger := &nfLogger{
		engineStop:       make(chan struct{}),
		processedPackets: make(chan []Packet, PacketsQueueSize),
		packetsToProcess: make(chan []Packet, PacketsQueueSize),
		nfloggers:        []*nfLog{},
		ipv4groupSource:  ipv4groupSource,
		ipv4groupDest:    ipv4groupDest,
		ipv6groupSource:  ipv6groupSource,
		ipv6groupDest:    ipv6groupDest,
	}

	for i := 0; i < PacketsQueueSize; i++ {
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

				parts := strings.SplitN(p.Prefix, ":", 2)
				contextID, extSrvID := parts[0], parts[1]

				record := collector.FlowRecord{
					ContextID: contextID,
					// Tags:            context.Annotations,
					Action:          "accept",
					Mode:            "NA",
					SourceIP:        p.SourceAddr.String(),
					DestinationIP:   p.DestinationAddr.String(),
					DestinationPort: 0,
				}

				if p.Direction == IPSource {
					record.SourceID = extSrvID
				} else {
					record.DestinationID = extSrvID
				}

				zap.L().Warn(fmt.Sprintf("LOG SourceIP %s DestIP %s SourceID %s DestinationID %s", record.SourceIP, record.DestinationIP, record.SourceID, record.DestinationID))
			}
			a.packetsToProcess <- ps

		case <-a.engineStop:
			return
		}
	}
}
