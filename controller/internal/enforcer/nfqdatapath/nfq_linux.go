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
	} else if netPacket.IPProto == packet.IPProtocolTCP {
		tcpConn, processError = d.processNetworkTCPPackets(netPacket)
	} else if netPacket.IPProto == packet.IPProtocolUDP {
		udpConn, processError = d.ProcessNetworkUDPPacket(netPacket)
	} else {
		processError = fmt.Errorf("invalid ip protocol: %d", netPacket.IPProto)

	}

	if processError != nil {
		length := uint32(len(p.Buffer))
		buffer := p.Buffer
		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), 0, uint32(p.Mark), length, uint32(p.ID), buffer)
		var value interface{}
		var err error
		if netPacket.IPProto == packet.IPProtocolTCP {
			if tcpConn == nil {
				return
			}
			value, err = d.packetTracingCache.Get(tcpConn.Context.ID())
		}
		if netPacket.IPProto == packet.IPProtocolUDP {
			if udpConn == nil {
				return
			}
			value, err = d.packetTracingCache.Get(udpConn.Context.ID())
		}

		if err == nil {
			if packettracing.IsApplicationPacketTraced(value.(*tracingCacheEntry).direction) {
				report := &collector.PacketReport{}
				if netPacket.IPProto == packet.IPProtocolTCP {
					report.TCPFlags = int(netPacket.TCPFlags)
					report.Protocol = int(packet.IPProtocolTCP)
					if tcpConn != nil {
						report.Encrypt = tcpConn.ServiceConnection
						report.Claims = tcpConn.Context.Identity().GetSlice()
						report.PUID = tcpConn.Context.ManagementID()
					}
				} else if netPacket.IPProto == packet.IPProtocolUDP {
					report.Protocol = int(packet.IPProtocolUDP)
					if udpConn != nil {
						report.Encrypt = udpConn.ServiceConnection
						report.Claims = udpConn.Context.Identity().GetSlice()
						report.PUID = udpConn.Context.ManagementID()
					}
				}

				//this is getting dropped so nothing on this
				report.DestinationIP = netPacket.DestinationAddress.String()
				report.SourceIP = netPacket.SourceAddress.String()
				report.DestinationPort = int(netPacket.DestinationPort)
				report.SourcePort = int(netPacket.SourcePort)
				report.DropReason = processError.Error()
				report.Length = int(netPacket.IPTotalLength)
				report.Mark = p.Mark
				report.PacketID, _ = strconv.Atoi(netPacket.ID())
				report.TriremePacket = true
				report.Event = packettracing.PacketDropped
				d.collector.CollectPacketEvent(report)
			}

		}

		return
	}

	if netPacket.IPProto == packet.IPProtocolTCP {
		// // Accept the packet
		buffer := make([]byte, len(netPacket.Buffer)+netPacket.TCPOptionLength()+netPacket.TCPDataLength())
		copyIndex := copy(buffer, netPacket.Buffer)
		copyIndex += copy(buffer[copyIndex:], netPacket.GetTCPOptions())
		copyIndex += copy(buffer[copyIndex:], netPacket.GetTCPData())

		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), 1, uint32(p.Mark), uint32(copyIndex), uint32(p.ID), buffer)
	} else {
		// Buffer is already modified.
		buffer := make([]byte, len(netPacket.Buffer))
		copyIndex := copy(buffer, netPacket.Buffer)
		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), 1, uint32(p.Mark), uint32(copyIndex), uint32(p.ID), buffer)

	}
	var value interface{}
	if netPacket.IPProto == packet.IPProtocolTCP {
		if tcpConn == nil {
			return
		}
		value, err = d.packetTracingCache.Get(tcpConn.Context.ID())
	}
	if netPacket.IPProto == packet.IPProtocolUDP {
		if udpConn == nil {
			return
		}
		value, err = d.packetTracingCache.Get(udpConn.Context.ID())
	}
	if err == nil {
		if packettracing.IsApplicationPacketTraced(value.(*tracingCacheEntry).direction) {

			report := &collector.PacketReport{}
			if netPacket.IPProto == packet.IPProtocolTCP {
				report.TCPFlags = int(netPacket.TCPFlags)
				report.Protocol = int(packet.IPProtocolTCP)
				if tcpConn != nil {
					report.Encrypt = tcpConn.ServiceConnection
					report.Claims = tcpConn.Context.Identity().GetSlice()
					report.PUID = tcpConn.Context.ManagementID()
				}
			} else if netPacket.IPProto == packet.IPProtocolUDP {
				report.Protocol = int(packet.IPProtocolUDP)
				if udpConn != nil {
					report.Encrypt = udpConn.ServiceConnection
					report.Claims = udpConn.Context.Identity().GetSlice()
					report.PUID = udpConn.Context.ManagementID()
				}
			}
			report.DestinationIP = netPacket.DestinationAddress.String()
			report.SourceIP = netPacket.SourceAddress.String()
			report.DestinationPort = int(netPacket.DestinationPort)
			report.SourcePort = int(netPacket.SourcePort)
			report.DropReason = ""
			report.Length = int(netPacket.IPTotalLength)
			report.Mark = p.Mark
			report.PacketID, _ = strconv.Atoi(netPacket.ID())
			report.Protocol = int(netPacket.IPProto)
			report.TriremePacket = true
			report.Event = packettracing.PacketSent
			d.collector.CollectPacketEvent(report)
		}
		//

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
	} else if appPacket.IPProto == packet.IPProtocolTCP {
		tcpConn, processError = d.processApplicationTCPPackets(appPacket)
	} else if appPacket.IPProto == packet.IPProtocolUDP {
		udpConn, processError = d.ProcessApplicationUDPPacket(appPacket)
	} else {
		processError = fmt.Errorf("invalid ip protocol: %d", appPacket.IPProto)
	}

	if processError != nil {
		length := uint32(len(p.Buffer))
		buffer := p.Buffer
		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), 0, uint32(p.Mark), length, uint32(p.ID), buffer)

		if value, err := d.packetTracingCache.Get(tcpConn.Context.ID()); err == nil {
			if packettracing.IsApplicationPacketTraced(value.(*tracingCacheEntry).direction) {
				report := &collector.PacketReport{}
				if appPacket.IPProto == packet.IPProtocolTCP {
					report.TCPFlags = int(appPacket.TCPFlags)
					report.Protocol = int(packet.IPProtocolTCP)
					if tcpConn != nil {
						report.Encrypt = tcpConn.ServiceConnection
						//report.Claims = tcpConn.Context.Identity().GetSlice()
						report.PUID = tcpConn.Context.ManagementID()
					}
				} else if appPacket.IPProto == packet.IPProtocolUDP {
					report.Protocol = int(packet.IPProtocolUDP)
					if udpConn != nil {
						report.Encrypt = udpConn.ServiceConnection
						//report.Claims = udpConn.Context.Identity().GetSlice()
						report.PUID = udpConn.Context.ManagementID()
					}
				}

				//this is getting dropped so nothing on this
				report.DestinationIP = appPacket.DestinationAddress.String()
				report.SourceIP = appPacket.SourceAddress.String()
				report.DestinationPort = int(appPacket.DestinationPort)
				report.SourcePort = int(appPacket.SourcePort)
				report.DropReason = processError.Error()
				report.Length = int(appPacket.IPTotalLength)
				report.Mark = p.Mark
				report.PacketID, _ = strconv.Atoi(appPacket.ID())
				report.TriremePacket = true
				report.Event = packettracing.PacketDropped
				d.collector.CollectPacketEvent(report)
			}

		}
		return
	}

	if appPacket.IPProto == packet.IPProtocolTCP {
		// Accept the packet
		buffer := make([]byte, len(appPacket.Buffer)+appPacket.TCPOptionLength()+appPacket.TCPDataLength())
		copyIndex := copy(buffer, appPacket.Buffer)
		copyIndex += copy(buffer[copyIndex:], appPacket.GetTCPOptions())
		copyIndex += copy(buffer[copyIndex:], appPacket.GetTCPData())

		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), 1, uint32(p.Mark), uint32(copyIndex), uint32(p.ID), buffer)

	} else {
		buffer := make([]byte, len(appPacket.Buffer))
		copyIndex := copy(buffer, appPacket.Buffer)
		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), 1, uint32(p.Mark), uint32(copyIndex), uint32(p.ID), buffer)

	}

	if value, err := d.packetTracingCache.Get(tcpConn.Context.ID()); err == nil {
		if packettracing.IsApplicationPacketTraced(value.(*tracingCacheEntry).direction) {

			report := &collector.PacketReport{}
			if appPacket.IPProto == packet.IPProtocolTCP {
				report.TCPFlags = int(appPacket.TCPFlags)
				report.Protocol = int(packet.IPProtocolTCP)
				if tcpConn != nil {
					report.Encrypt = tcpConn.ServiceConnection
					//report.Claims = tcpConn.Context.Identity().GetSlice()
					report.PUID = tcpConn.Context.ManagementID()
				}
			} else if appPacket.IPProto == packet.IPProtocolUDP {
				report.Protocol = int(packet.IPProtocolUDP)
				if udpConn != nil {
					report.Encrypt = udpConn.ServiceConnection
					//report.Claims = udpConn.Context.Identity().GetSlice()
					report.PUID = udpConn.Context.ManagementID()
				}
			}
			report.DestinationIP = appPacket.DestinationAddress.String()
			report.SourceIP = appPacket.SourceAddress.String()
			report.DestinationPort = int(appPacket.DestinationPort)
			report.SourcePort = int(appPacket.SourcePort)
			report.DropReason = ""
			report.Length = int(appPacket.IPTotalLength)
			report.Mark = p.Mark
			report.PacketID, _ = strconv.Atoi(appPacket.ID())
			report.Protocol = int(appPacket.IPProto)
			report.TriremePacket = true
			report.Event = packettracing.PacketSent
			d.collector.CollectPacketEvent(report)

		}
		//

	}

}
