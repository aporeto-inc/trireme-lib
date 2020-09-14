// +build linux

package nfqdatapath

// Go libraries
import (
	"context"
	"fmt"
	"strconv"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.uber.org/zap"
)

func errorCallback(err error, _ interface{}) {
	zap.L().Error("Error while processing packets on queue", zap.Error(err))
}

var nf *nfqueue.Nfqueue

func (d *Datapath) callback(a nfqueue.Attribute) int {
	fn := func(a nfqueue.Attribute) int {
		id := *a.PacketID
		// Just print out the id and payload of the nfqueue packet
		fmt.Printf("[%d]\t%v\n", id, *a.Payload)
		nf.SetVerdict(id, nfqueue.NfAccept)
		return 0
	}

	mark := *a.Mark

	if mark == 5679 {
		d.processNetworkPacketsFromNFQ(packet)
		return 0
	}

	d.processApplicationPacketsFromNFQ(packet)
	return 0
}

// startNetworkInterceptor will the process that processes  packets from the network
// Still has one more copy than needed. Can be improved.
func (d *Datapath) startInterceptor(ctx context.Context) {
	config := nfqueue.Config{
		NfQueue:      0,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  500,
		Copymode:     nfqueue.NfQnlCopyPacket,
		ReadTimeout:  10 * time.Millisecond,
		WriteTimeout: 15 * time.Millisecond,
	}

	nf, err = nfqueue.Open(&config)
	if err != nil {
		fmt.Println("could not open nfqueue socket:", err)
		return
	}

	ctx := context.Background()

	err = nf.Register(ctx, d.callback)
	if err != nil {
		fmt.Println("fsfdsfsdfsdfdsfsdfsdfdsf")
	}
}

// processNetworkPacketsFromNFQ processes packets arriving from the network in an NF queue
func (d *Datapath) processNetworkPacketsFromNFQ(a nfqueue.Attribute) {
	// Parse the packet - drop if parsing fails
	netPacket, err := packet.New(packet.PacketTypeNetwork, *a.Payload, strconv.Itoa(int(*a.Mark)), true)
	var processError error
	var tcpConn *connection.TCPConnection
	var udpConn *connection.UDPConnection
	if err != nil {
		netPacket.Print(packet.PacketFailureCreate, d.packetLogs)
	} else if netPacket.IPProto() == packet.IPProtocolTCP {
		tcpConn, processError = d.processNetworkTCPPackets(netPacket)
	} else if netPacket.IPProto() == packet.IPProtocolUDP {
		udpConn, processError = d.ProcessNetworkUDPPacket(netPacket)
	} else {
		processError = fmt.Errorf("invalid ip protocol: %d", netPacket.IPProto())

	}

	// TODO: Use error types and handle it in switch case here
	if processError != nil {
		zap.L().Debug("Dropping packet on network path",
			zap.Error(processError),
			zap.String("SourceIP", netPacket.SourceAddress().String()),
			zap.String("DestiatnionIP", netPacket.DestinationAddress().String()),
			zap.Int("SourcePort", int(netPacket.SourcePort())),
			zap.Int("DestinationPort", int(netPacket.DestPort())),
			zap.Int("Protocol", int(netPacket.IPProto())),
			zap.String("Flags", packet.TCPFlagsToStr(netPacket.GetTCPFlags())),
		)

		nf.SetVerdict(*a.PacketID, nfqueue.NfDrop)

		if netPacket.IPProto() == packet.IPProtocolTCP {
			d.collectTCPPacket(&debugpacketmessage{
				Mark:    int(*a.Mark),
				p:       netPacket,
				tcpConn: tcpConn,
				udpConn: nil,
				err:     processError,
				network: true,
			})
		} else if netPacket.IPProto() == packet.IPProtocolUDP {
			d.collectUDPPacket(&debugpacketmessage{
				Mark:    int(*a.Mark),
				p:       netPacket,
				tcpConn: nil,
				udpConn: udpConn,
				err:     processError,
				network: true,
			})
		}

		return
	}

	// v := uint32(1)
	// if tcpConn != nil {
	// 	if !tcpConn.PingConfig.Passthrough && tcpConn.PingConfig.Type != claimsheader.PingTypeNone {
	// 		v = uint32(0)
	// 	}
	// }

	if netPacket.IPProto() == packet.IPProtocolTCP {
		// // Accept the packet
		buffer := make([]byte, netPacket.IPTotalLen())
		copyIndex := copy(buffer, netPacket.GetBuffer(0))
		copyIndex += copy(buffer[copyIndex:], netPacket.GetTCPOptions())
		copyIndex += copy(buffer[copyIndex:], netPacket.GetTCPData())

		nf.SetVerdictModPacket(*a.PacketID, nfqueue.NF_ACCEPT, buffer)
	} else {
		nf.SetVerdictModPacket(*a.PacketID, nfqueue.NF_ACCEPT, netPacket.GetBuffer(0))
	}

	if netPacket.IPProto() == packet.IPProtocolTCP {
		d.collectTCPPacket(&debugpacketmessage{
			Mark:    int(*a.Mark),
			p:       netPacket,
			tcpConn: tcpConn,
			udpConn: nil,
			err:     nil,
			network: true,
		})
	} else if netPacket.IPProto() == packet.IPProtocolUDP {
		d.collectUDPPacket(&debugpacketmessage{
			Mark:    int(*a.Mark),
			p:       netPacket,
			tcpConn: nil,
			udpConn: udpConn,
			err:     nil,
			network: true,
		})
	}
}

// processApplicationPackets processes packets arriving from an application and are destined to the network
func (d *Datapath) processApplicationPacketsFromNFQ(a nfqueue.Attribute) {

	// Being liberal on what we transmit - malformed TCP packets are let go
	// We are strict on what we accept on the other side, but we don't block
	// lots of things at the ingress to the network
	appPacket, err := packet.New(packet.PacketTypeApplication, p.Data, strconv.Itoa(int(*a.Mark)), true)

	var processError error
	var tcpConn *connection.TCPConnection
	var udpConn *connection.UDPConnection
	if err != nil {
		appPacket.Print(packet.PacketFailureCreate, d.packetLogs)
	} else if appPacket.IPProto() == packet.IPProtocolTCP {
		tcpConn, processError = d.processApplicationTCPPackets(appPacket)
	} else if appPacket.IPProto() == packet.IPProtocolUDP {
		udpConn, processError = d.ProcessApplicationUDPPacket(appPacket)
	} else {
		processError = fmt.Errorf("invalid ip protocol: %d", appPacket.IPProto())
	}

	if processError != nil {
		zap.L().Debug("Dropping packet on app path",
			zap.Error(processError),
			zap.String("SourceIP", appPacket.SourceAddress().String()),
			zap.String("DestiatnionIP", appPacket.DestinationAddress().String()),
			zap.Int("SourcePort", int(appPacket.SourcePort())),
			zap.Int("DestinationPort", int(appPacket.DestPort())),
			zap.Int("Protocol", int(appPacket.IPProto())),
			zap.String("Flags", packet.TCPFlagsToStr(appPacket.GetTCPFlags())),
		)

		p.SetVerdictModPacket(*a.PacketID, nfqueue.NfDrop)

		if appPacket.IPProto() == packet.IPProtocolTCP {

			d.collectTCPPacket(&debugpacketmessage{
				Mark:    int(*a.Mark),
				p:       appPacket,
				tcpConn: tcpConn,
				udpConn: nil,
				err:     processError,
				network: false,
			})
		} else if appPacket.IPProto() == packet.IPProtocolUDP {
			d.collectUDPPacket(&debugpacketmessage{
				Mark:    int(*a.Mark),
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

		nf.SetVerdictModPacket(*a.PacketID, nfqueue.NF_ACCEPT, buffer)
	} else {
		nf.SetVerdictModPacket(*a.PacketID, nfqueue.NF_ACCEPT, appPacket.GetBuffer(0))
	}

	if appPacket.IPProto() == packet.IPProtocolTCP {
		d.collectTCPPacket(&debugpacketmessage{
			Mark:    int(*a.Mark),
			p:       appPacket,
			tcpConn: tcpConn,
			udpConn: nil,
			err:     nil,
			network: false,
		})
	} else if appPacket.IPProto() == packet.IPProtocolUDP {
		d.collectUDPPacket(&debugpacketmessage{
			Mark:    int(*a.Mark),
			p:       appPacket,
			tcpConn: nil,
			udpConn: udpConn,
			err:     nil,
			network: false,
		})
	}
}

func (d *Datapath) cleanupPlatform() {}
