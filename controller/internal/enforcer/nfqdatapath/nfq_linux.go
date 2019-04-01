// +build linux

package nfqdatapath

// Go libraries
import (
	"context"
	"fmt"
	"strconv"
	"time"

	nfqueue "go.aporeto.io/netlink-go/nfqueue"
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/packettracing"
	"go.uber.org/zap"
)

func errorCallback(err error, _ interface{}) {
	zap.L().Error("Error while processing packets on queue", zap.Error(err))
}
func networkCallback(packet *nfqueue.NFPacket, d interface{}) {
	d.(*Datapath).processNetworkPacketsFromNFQ(packet)
}

func appCallBack(packet *nfqueue.NFPacket, d interface{}) {
	d.(*Datapath).processApplicationPacketsFromNFQ(packet)
}

// startNetworkInterceptor will the process that processes  packets from the network
// Still has one more copy than needed. Can be improved.
func (d *Datapath) startNetworkInterceptor(ctx context.Context) {
	var err error

	nfq := make([]nfqueue.Verdict, d.filterQueue.GetNumNetworkQueues())

	for i := uint16(0); i < d.filterQueue.GetNumNetworkQueues(); i++ {
		// Initialize all the queues
		nfq[i], err = nfqueue.CreateAndStartNfQueue(ctx, d.filterQueue.GetNetworkQueueStart()+i, d.filterQueue.GetNetworkQueueSize(), nfqueue.NfDefaultPacketSize, networkCallback, errorCallback, d)
		if err != nil {
			for retry := 0; retry < 5 && err != nil; retry++ {
				nfq[i], err = nfqueue.CreateAndStartNfQueue(ctx, d.filterQueue.GetNetworkQueueStart()+i, d.filterQueue.GetNetworkQueueSize(), nfqueue.NfDefaultPacketSize, networkCallback, errorCallback, d)
				<-time.After(3 * time.Second)
			}
			if err != nil {
				zap.L().Fatal("Unable to initialize netfilter queue", zap.Error(err))
			}
		}
	}
}

// startApplicationInterceptor will create a interceptor that processes
// packets originated from a local application
func (d *Datapath) startApplicationInterceptor(ctx context.Context) {
	var err error

	nfq := make([]nfqueue.Verdict, d.filterQueue.GetNumApplicationQueues())

	for i := uint16(0); i < d.filterQueue.GetNumApplicationQueues(); i++ {
		nfq[i], err = nfqueue.CreateAndStartNfQueue(ctx, d.filterQueue.GetApplicationQueueStart()+i, d.filterQueue.GetApplicationQueueSize(), nfqueue.NfDefaultPacketSize, appCallBack, errorCallback, d)

		if err != nil {
			for retry := 0; retry < 5 && err != nil; retry++ {
				nfq[i], err = nfqueue.CreateAndStartNfQueue(ctx, d.filterQueue.GetApplicationQueueStart()+i, d.filterQueue.GetApplicationQueueSize(), nfqueue.NfDefaultPacketSize, appCallBack, errorCallback, d)
				<-time.After(3 * time.Second)
			}
			if err != nil {
				zap.L().Fatal("Unable to initialize netfilter queue", zap.Int("QueueNum", int(d.filterQueue.GetNetworkQueueStart()+i)), zap.Error(err))
			}

		}
	}
}

// processNetworkPacketsFromNFQ processes packets arriving from the network in an NF queue
func (d *Datapath) processNetworkPacketsFromNFQ(p *nfqueue.NFPacket) {

	// Parse the packet - drop if parsing fails
	netPacket, err := packet.New(packet.PacketTypeNetwork, p.Buffer, strconv.Itoa(p.Mark), true)
	var processError error
	var tcpConn *connection.TCPConnection
	var udpConn *connection.UDPConnection
	if err != nil {
		netPacket.Print(packet.PacketFailureCreate)
	} else if netPacket.IPProto() == packet.IPProtocolTCP {
		tcpConn, processError = d.processNetworkTCPPackets(netPacket)
	} else if netPacket.IPProto() == packet.IPProtocolUDP {
		udpConn, processError = d.ProcessNetworkUDPPacket(netPacket)
	} else {
		processError = fmt.Errorf("invalid ip protocol: %d", netPacket.IPProto())

	}

	if processError != nil {
		zap.L().Debug("Dropping packet on network path",
			zap.Error(err),
			zap.String("SourceIP", netPacket.SourceAddress().String()),
			zap.String("DestiatnionIP", netPacket.DestinationAddress().String()),
			zap.Int("SourcePort", int(netPacket.SourcePort())),
			zap.Int("DestinationPort", int(netPacket.DestPort())),
			zap.Int("Protocol", int(netPacket.IPProto())),
		)
		length := uint32(len(p.Buffer))
		buffer := p.Buffer
		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), 0, uint32(p.Mark), length, uint32(p.ID), buffer)
		if netPacket.IPProto() == packet.IPProtocolTCP {
			d.collectTCPPacket(&debugpacketmessage{
				Mark:    p.Mark,
				p:       netPacket,
				tcpConn: tcpConn,
				udpConn: nil,
				err:     processError,
				network: true,
			})
		} else if netPacket.IPProto() == packet.IPProtocolUDP {
			d.collectUDPPacket(&debugpacketmessage{
				Mark:    p.Mark,
				p:       netPacket,
				tcpConn: nil,
				udpConn: udpConn,
				err:     processError,
				network: true,
			})
		}

		return
	}

	if netPacket.IPProto() == packet.IPProtocolTCP {
		// // Accept the packet
		buffer := make([]byte, netPacket.IPTotalLen())
		copyIndex := copy(buffer, netPacket.GetBuffer(0))
		copyIndex += copy(buffer[copyIndex:], netPacket.GetTCPOptions())
		copyIndex += copy(buffer[copyIndex:], netPacket.GetTCPData())

		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), 1, uint32(p.Mark), uint32(copyIndex), uint32(p.ID), buffer)
	} else {
		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), 1, uint32(p.Mark), uint32(len(netPacket.GetBuffer(0))), uint32(p.ID), netPacket.GetBuffer(0))
	}
	if netPacket.IPProto() == packet.IPProtocolTCP {
		d.collectTCPPacket(&debugpacketmessage{
			Mark:    p.Mark,
			p:       netPacket,
			tcpConn: tcpConn,
			udpConn: nil,
			err:     nil,
			network: true,
		})
	} else if netPacket.IPProto() == packet.IPProtocolUDP {
		d.collectUDPPacket(&debugpacketmessage{
			Mark:    p.Mark,
			p:       netPacket,
			tcpConn: nil,
			udpConn: udpConn,
			err:     nil,
			network: true,
		})
	}

}

// processApplicationPackets processes packets arriving from an application and are destined to the network
func (d *Datapath) processApplicationPacketsFromNFQ(p *nfqueue.NFPacket) {

	// Being liberal on what we transmit - malformed TCP packets are let go
	// We are strict on what we accept on the other side, but we don't block
	// lots of things at the ingress to the network
	appPacket, err := packet.New(packet.PacketTypeApplication, p.Buffer, strconv.Itoa(p.Mark), true)

	var processError error
	var tcpConn *connection.TCPConnection
	var udpConn *connection.UDPConnection
	if err != nil {
		appPacket.Print(packet.PacketFailureCreate)
	} else if appPacket.IPProto() == packet.IPProtocolTCP {
		tcpConn, processError = d.processApplicationTCPPackets(appPacket)
	} else if appPacket.IPProto() == packet.IPProtocolUDP {
		udpConn, processError = d.ProcessApplicationUDPPacket(appPacket)
	} else {
		processError = fmt.Errorf("invalid ip protocol: %d", appPacket.IPProto())
	}
	if processError != nil {
		length := uint32(len(p.Buffer))
		buffer := p.Buffer
		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), 0, uint32(p.Mark), length, uint32(p.ID), buffer)
		if appPacket.IPProto() == packet.IPProtocolTCP {

			d.collectTCPPacket(&debugpacketmessage{
				Mark:    p.Mark,
				p:       appPacket,
				tcpConn: tcpConn,
				udpConn: nil,
				err:     processError,
				network: false,
			})
		} else if appPacket.IPProto() == packet.IPProtocolUDP {
			d.collectUDPPacket(&debugpacketmessage{
				Mark:    p.Mark,
				p:       appPacket,
				tcpConn: nil,
				udpConn: udpConn,
				err:     processError,
				network: false,
			})
		}
		return
	}

	if appPacket.IPProto() == packet.IPProtocolTCP {
		// Accept the packet
		buffer := make([]byte, appPacket.IPTotalLen())
		copyIndex := copy(buffer, appPacket.GetBuffer(0))
		copyIndex += copy(buffer[copyIndex:], appPacket.GetTCPOptions())
		copyIndex += copy(buffer[copyIndex:], appPacket.GetTCPData())

		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), 1, uint32(p.Mark), uint32(copyIndex), uint32(p.ID), buffer)

	} else {
		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), 1, uint32(p.Mark), uint32(len(appPacket.GetBuffer(0))), uint32(p.ID), appPacket.GetBuffer(0))
	}
	if appPacket.IPProto() == packet.IPProtocolTCP {
		d.collectTCPPacket(&debugpacketmessage{
			Mark:    p.Mark,
			p:       appPacket,
			tcpConn: tcpConn,
			udpConn: nil,
			err:     nil,
			network: false,
		})
	} else if appPacket.IPProto() == packet.IPProtocolUDP {
		d.collectUDPPacket(&debugpacketmessage{
			Mark:    p.Mark,
			p:       appPacket,
			tcpConn: nil,
			udpConn: udpConn,
			err:     nil,
			network: false,
		})
	}

}

func (d *Datapath) collectUDPPacket(msg *debugpacketmessage) {
	var value interface{}
	var err error
	report := &collector.PacketReport{}
	if msg.udpConn == nil {
		if d.puFromIP == nil {
			return
		}
		if value, err = d.packetTracingCache.Get(d.puFromIP.ID()); err != nil {
			//not being traced return
			return
		}

		report.Claims = d.puFromIP.Identity().GetSlice()
		report.PUID = d.puFromIP.ManagementID()
		report.Encrypt = false

	} else {
		//udpConn is not nil
		if value, err = d.packetTracingCache.Get(msg.udpConn.Context.ID()); err != nil {
			return
		}
		report.Encrypt = msg.udpConn.ServiceConnection
		report.Claims = msg.udpConn.Context.Identity().GetSlice()
		report.PUID = msg.udpConn.Context.ManagementID()
	}

	if msg.network && !packettracing.IsNetworkPacketTraced(value.(*tracingCacheEntry).direction) {
		return
	} else if !msg.network && !packettracing.IsApplicationPacketTraced(value.(*tracingCacheEntry).direction) {
		return
	}
	report.Protocol = int(packet.IPProtocolUDP)
	report.DestinationIP = msg.p.DestinationAddress().String()
	report.SourceIP = msg.p.SourceAddress().String()
	report.DestinationPort = int(msg.p.DestPort())
	report.SourcePort = int(msg.p.SourcePort())
	if msg.err != nil {
		report.DropReason = msg.err.Error()
		report.Event = packettracing.PacketDropped
	} else {
		report.DropReason = ""
		report.Event = packettracing.PacketReceived
	}
	report.Length = int(msg.p.IPTotalLen())
	report.Mark = msg.Mark
	report.PacketID, _ = strconv.Atoi(msg.p.ID())
	report.TriremePacket = true

	d.collector.CollectPacketEvent(report)
}

func (d *Datapath) collectTCPPacket(msg *debugpacketmessage) {
	var value interface{}
	var err error
	report := &collector.PacketReport{}

	if msg.tcpConn == nil {
		if d.puFromIP == nil {
			return
		}

		if value, err = d.packetTracingCache.Get(d.puFromIP.ID()); err != nil {
			//not being traced return
			return
		}

		report.Claims = d.puFromIP.Identity().GetSlice()
		report.PUID = d.puFromIP.ManagementID()
		report.Encrypt = false

	} else {

		if value, err = d.packetTracingCache.Get(msg.tcpConn.Context.ID()); err != nil {
			//not being traced return
			return
		}
		//tcpConn is not nil
		report.Encrypt = msg.tcpConn.ServiceConnection
		report.Claims = msg.tcpConn.Context.Identity().GetSlice()
		report.PUID = msg.tcpConn.Context.ManagementID()
	}

	if msg.network && !packettracing.IsNetworkPacketTraced(value.(*tracingCacheEntry).direction) {
		return
	} else if !msg.network && !packettracing.IsApplicationPacketTraced(value.(*tracingCacheEntry).direction) {
		return
	}

	report.TCPFlags = int(msg.p.GetTCPFlags())
	report.Protocol = int(packet.IPProtocolTCP)
	report.DestinationIP = msg.p.DestinationAddress().String()
	report.SourceIP = msg.p.SourceAddress().String()
	report.DestinationPort = int(msg.p.DestPort())
	report.SourcePort = int(msg.p.SourcePort())
	if msg.err != nil {
		report.DropReason = msg.err.Error()
		report.Event = packettracing.PacketDropped
	} else {
		report.DropReason = ""
		report.Event = packettracing.PacketReceived
	}
	report.Length = int(msg.p.IPTotalLen())
	report.Mark = msg.Mark
	report.PacketID, _ = strconv.Atoi(msg.p.ID())
	report.TriremePacket = true

	d.collector.CollectPacketEvent(report)

}
