// +build linux

package nfqdatapath

// Go libraries
import (
	"context"
	"fmt"
	"strconv"
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/counters"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/constants"
	markconstants "go.aporeto.io/enforcerd/trireme-lib/utils/constants"
	nfqueue "go.aporeto.io/netlink-go/nfqueue"
	"go.uber.org/zap"
)

const (
	// nfq actions.
	allow  = 1
	drop   = 0
	repeat = 4
)

const (
	// max
	maxTriesNfq = 5
)

func (d *Datapath) errorCallback(err error, _ interface{}) {
	zap.L().Error("Error while processing packets on queue", zap.Error(err))
}

func (d *Datapath) callback(packet *nfqueue.NFPacket, _ interface{}) {
	packet.Mark = packet.Mark - int(packet.QueueHandle.QueueNum)*constants.QueueBalanceFactor

	if packet.Mark == int(constants.DefaultInputMark) {
		d.processNetworkPacketsFromNFQ(packet)
		return
	}

	packet.Mark = packet.Mark / d.filterQueue.GetNumQueues()
	d.processApplicationPacketsFromNFQ(packet)
}

func (d *Datapath) startInterceptor(ctx context.Context) {

	var err error
LOOP:
	for i := 0; i < d.filterQueue.GetNumQueues(); i++ {
		// Initialize all the queues
		for tries := 0; tries < maxTriesNfq; tries++ {
			if _, err = nfqueue.CreateAndStartNfQueue(ctx, uint16(i), 4096, nfqueue.NfDefaultPacketSize, d.callback, d.errorCallback, nil); err == nil {
				continue LOOP
			}

			time.Sleep(1 * time.Second)
		}

		zap.L().Fatal("Unable to initialize netfilter queue", zap.Error(err))
	}
}

// processNetworkPacketsFromNFQ processes packets arriving from the network in an NF queue
func (d *Datapath) processNetworkPacketsFromNFQ(p *nfqueue.NFPacket) {
	var processError error
	var tcpConn *connection.TCPConnection
	var udpConn *connection.UDPConnection
	var processAfterVerdict func()

	netPacket := &packet.Packet{}
	err := netPacket.NewPacket(packet.PacketTypeNetwork, p.Buffer, strconv.Itoa(p.Mark), true)
	if err != nil {
		counters.CounterError(counters.ErrCorruptPacket, err) //nolint
		zap.L().Debug("Dropping corrupted packet on network path", zap.Error(err))
		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), drop, 0, 0, uint32(p.ID), []byte{0})
		return
	} else if netPacket.IPProto() == packet.IPProtocolTCP {
		tcpConn, processAfterVerdict, processError = d.processNetworkTCPPackets(netPacket)
	} else if netPacket.IPProto() == packet.IPProtocolUDP {
		udpConn, processError = d.ProcessNetworkUDPPacket(netPacket)
	} else if netPacket.IPProto() == packet.IPProtocolICMP {
		icmpType, icmpCode := netPacket.GetICMPTypeCode()
		context, err := d.contextFromIP(false, netPacket.Mark, 0, packet.IPProtocolICMP)

		if err == nil {
			action := d.processNetworkICMPPacket(context, netPacket, icmpType, icmpCode)
			if action == icmpAccept {
				p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), allow, 0, uint32(len(netPacket.GetBuffer(0))), uint32(p.ID), netPacket.GetBuffer(0))
				return
			}
		}

		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), drop, 0, uint32(len(netPacket.GetBuffer(0))), uint32(p.ID), netPacket.GetBuffer(0))
		zap.L().Debug("dropping Network ICMP Packet",
			zap.Error(err),
			zap.String("SourceIP", netPacket.SourceAddress().String()),
			zap.String("DestinationIP", netPacket.DestinationAddress().String()),
			zap.Int8("icmp type", icmpType),
			zap.Int8("icmp code", icmpCode))

		return
	} else {
		processError = counters.CounterError(counters.ErrInvalidProtocol, fmt.Errorf("Invalid Protocol %d", int(netPacket.IPProto())))
	}

	// TODO: Use error types and handle it in switch case here

	if processError != nil {
		if processError != errDropPingNetSynAck && processError != errHandshakePacket && processError != errDropQueuedPacket {
			zap.L().Debug("Dropping packet on network path",
				zap.Error(processError),
				zap.String("SourceIP", netPacket.SourceAddress().String()),
				zap.String("DestinationIP", netPacket.DestinationAddress().String()),
				zap.Int("SourcePort", int(netPacket.SourcePort())),
				zap.Int("DestinationPort", int(netPacket.DestPort())),
				zap.Int("Protocol", int(netPacket.IPProto())),
				zap.String("Flags", packet.TCPFlagsToStr(netPacket.GetTCPFlags())),
			)
		}

		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), drop, uint32(p.Mark), 0, uint32(p.ID), []byte{0})

		if processError != errDropPingNetSynAck {
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
		}

		return
	}

	if netPacket.IPProto() == packet.IPProtocolTCP {
		if netPacket.SetConnmark {
			p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), repeat, markconstants.PacketMarkToSetConnmark, uint32(len(netPacket.GetBuffer(0))), uint32(p.ID), netPacket.GetBuffer(0))
		} else {
			if d.serviceMeshType == policy.Istio {
				p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), allow, markconstants.IstioPacketMark, uint32(len(netPacket.GetBuffer(0))), uint32(p.ID), netPacket.GetBuffer(0))
			} else {
				p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), allow, 0, uint32(len(netPacket.GetBuffer(0))), uint32(p.ID), netPacket.GetBuffer(0))
			}
		}
	} else {
		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), allow, 0, uint32(len(netPacket.GetBuffer(0))), uint32(p.ID), netPacket.GetBuffer(0))
	}

	if processAfterVerdict != nil {
		processAfterVerdict()
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

	var processError error
	var tcpConn *connection.TCPConnection
	var udpConn *connection.UDPConnection

	appPacket := &packet.Packet{}
	err := appPacket.NewPacket(packet.PacketTypeApplication, p.Buffer, strconv.Itoa(p.Mark), true)

	if err != nil {
		zap.L().Debug("Dropping corrupted packet on application path", zap.Error(err))
		counters.CounterError(counters.ErrCorruptPacket, err) //nolint
		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), drop, 0, 0, uint32(p.ID), []byte{0})
		return
	} else if appPacket.IPProto() == packet.IPProtocolTCP {
		tcpConn, processError = d.processApplicationTCPPackets(appPacket)
	} else if appPacket.IPProto() == packet.IPProtocolUDP {
		udpConn, processError = d.ProcessApplicationUDPPacket(appPacket)
	} else if appPacket.IPProto() == packet.IPProtocolICMP {
		icmpType, icmpCode := appPacket.GetICMPTypeCode()
		context, err := d.contextFromIP(true, appPacket.Mark, 0, packet.IPProtocolICMP)

		if err == nil {
			action := d.processApplicationICMPPacket(context, appPacket, icmpType, icmpCode)
			if action == icmpAccept {
				p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), allow, 0, uint32(len(appPacket.GetBuffer(0))), uint32(p.ID), appPacket.GetBuffer(0))
				return
			}
		}

		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), drop, 0, uint32(len(appPacket.GetBuffer(0))), uint32(p.ID), appPacket.GetBuffer(0))
		zap.L().Debug("dropping Application ICMP Packet",
			zap.Error(err),
			zap.String("SourceIP", appPacket.SourceAddress().String()),
			zap.String("DestinationIP", appPacket.DestinationAddress().String()),
			zap.Int8("icmp type", icmpType),
			zap.Int8("icmp code", icmpCode))

		return
	} else {
		processError = counters.CounterError(counters.ErrInvalidProtocol, fmt.Errorf("Invalid Protocol %d", int(appPacket.IPProto())))
	}

	if processError != nil {
		if processError != errHandshakePacket && processError != errDropQueuedPacket {

			zap.L().Debug("Dropping packet on app path",
				zap.Error(processError),
				zap.String("SourceIP", appPacket.SourceAddress().String()),
				zap.String("DestinationIP", appPacket.DestinationAddress().String()),
				zap.Int("SourcePort", int(appPacket.SourcePort())),
				zap.Int("DestinationPort", int(appPacket.DestPort())),
				zap.Int("Protocol", int(appPacket.IPProto())),
				zap.String("Flags", packet.TCPFlagsToStr(appPacket.GetTCPFlags())),
			)
		}
		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), drop, uint32(p.Mark), 0, uint32(p.ID), []byte{0})

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
		if appPacket.SetConnmark {
			p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), repeat, markconstants.PacketMarkToSetConnmark, uint32(len(appPacket.GetBuffer(0))), uint32(p.ID), appPacket.GetBuffer(0))
		} else {
			if d.serviceMeshType == policy.Istio {
				p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), allow, markconstants.IstioPacketMark, uint32(len(appPacket.GetBuffer(0))), uint32(p.ID), appPacket.GetBuffer(0))
			} else {
				p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), allow, 0, uint32(len(appPacket.GetBuffer(0))), uint32(p.ID), appPacket.GetBuffer(0))
			}
		}
	} else {
		p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), allow, 0, uint32(len(appPacket.GetBuffer(0))), uint32(p.ID), appPacket.GetBuffer(0))
	}

	if appPacket.IPProto() == packet.IPProtocolTCP {
		var id string
		if tcpConn != nil {
			id = tcpConn.Context.ID()
		} else if d.puFromIP != nil {
			id = d.puFromIP.ID()
		}

		if _, err = d.packetTracingCache.Get(id); err == nil {
			d.collectTCPPacket(&debugpacketmessage{
				Mark:    p.Mark,
				p:       appPacket,
				tcpConn: tcpConn,
				udpConn: nil,
				err:     nil,
				network: false,
			})
		}

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

func (d *Datapath) cleanupPlatform() {}
