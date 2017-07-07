package nflog

// this code is a librarification the https://github.com/ncw/go-nflog-acctd

import (
	"fmt"
	"net"
	"sync"

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
}

// NewNFLogger returns a new NFLogger.
func NewNFLogger(ipv4groupSource, ipv4groupDest, ipv6groupSource, ipv6groupDest int) (NFLogger, error) {

	logger := &nfLogger{
		engineStop:       make(chan struct{}),
		processedPackets: make(chan []Packet, PacketsQueueSize),
		packetsToProcess: make(chan []Packet, PacketsQueueSize),
		nfloggers:        []*nfLog{},
	}

	for i := 0; i < PacketsQueueSize; i++ {
		logger.packetsToProcess <- make([]Packet, 0, 128)
	}

	configure := func(group int, ipType byte, direction IPDirection, prefixLen int) error {
		if group == 0 {
			return nil
		}
		l, err := newNfLog(group, ipType, direction, prefixLen, logger.packetsToProcess, logger.processedPackets)
		if err != nil {
			return err
		}
		logger.nfloggers = append(logger.nfloggers, l)

		return nil
	}

	if err := configure(ipv4groupSource, 4, IPSource, 32); err != nil {
		return nil, err
	}

	if err := configure(ipv4groupDest, 4, IPDest, 32); err != nil {
		return nil, err
	}

	if err := configure(ipv6groupSource, 6, IPSource, 64); err != nil {
		return nil, err
	}

	if err := configure(ipv6groupDest, 6, IPDest, 64); err != nil {
		return nil, err
	}

	return logger, nil
}

// Start starts the NFlogger.
func (a *nfLogger) Start() {

	a.engineWg.Add(1)

	for _, logger := range a.nfloggers {
		go logger.start()
	}

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

// type FlowRecord struct {
// 	ContextID       string
// 	Count           int
// 	SourceID        string
// 	DestinationID   string
// 	SourceIP        string
// 	DestinationIP   string
// 	DestinationPort uint16
// 	Tags            *policy.TagsMap
// 	Action          string
// 	Mode            string
// }

func (a *nfLogger) listen() {

	defer a.engineWg.Done()

	for {
		select {
		case ps := <-a.processedPackets:
			for _, p := range ps {
				zap.L().Warn(fmt.Sprintf("IP message %s Addr %s Size %d Prefix %s", p.Direction, net.IP(p.Addr), p.Length, p.Prefix))
			}
			a.packetsToProcess <- ps

		case <-a.engineStop:
			return
		}
	}
}
