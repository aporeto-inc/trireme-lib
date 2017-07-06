package nflog

// this code is a librarification the https://github.com/ncw/go-nflog-acctd

import (
	"fmt"
	"net"
	"sync"
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
func NewNFLogger(ipv4group, ipv6group int, direction IPDirection) NFLogger {

	logger := &nfLogger{
		engineStop:       make(chan struct{}),
		processedPackets: make(chan []Packet, PacketsQueueSize),
		packetsToProcess: make(chan []Packet, PacketsQueueSize),
		nfloggers:        []*nfLog{},
	}

	for i := 0; i < PacketsQueueSize; i++ {
		logger.packetsToProcess <- make([]Packet, 0, 128)
	}

	if ipv4group != 0 {
		logger.nfloggers = append(logger.nfloggers, newNfLog(ipv4group, 4, direction, 32, logger.packetsToProcess, logger.processedPackets))
	}
	if ipv6group != 0 {
		logger.nfloggers = append(logger.nfloggers, newNfLog(ipv6group, 6, direction, 64, logger.packetsToProcess, logger.processedPackets))
	}

	return logger
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

func (a *nfLogger) listen() {

	defer a.engineWg.Done()

	for {
		select {
		case ps := <-a.processedPackets:
			for _, p := range ps {
				fmt.Printf("IP message %s Addr %s Size %d", p.Direction, net.IP(p.Addr), p.Length)
			}
			a.packetsToProcess <- ps

		case <-a.engineStop:
			return
		}
	}
}
