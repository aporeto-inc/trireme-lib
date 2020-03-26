// +build windows

package nfqdatapath

import (
	"context"
	"fmt"
	"strconv"
	"unsafe"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/nflog"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/utils/frontman"
	"go.uber.org/zap"
)

func (d *Datapath) startFrontmanPacketFilter(_ context.Context, nflogger nflog.NFLogger) error {

	nflogWin := nflogger.(*nflog.NfLogWindows)

	packetCallback := func(packetInfoPtr, dataPtr uintptr) uintptr {

		packetInfo := *(*frontman.PacketInfo)(unsafe.Pointer(packetInfoPtr))                                   //nolint:govet
		packetBytes := (*[1 << 30]byte)(unsafe.Pointer(dataPtr))[:packetInfo.PacketSize:packetInfo.PacketSize] //nolint:govet

		var packetType int
		if packetInfo.Outbound != 0 {
			packetType = packet.PacketTypeApplication
		} else {
			packetType = packet.PacketTypeNetwork
		}

		// Parse the packet
		mark := int(packetInfo.Mark)
		parsedPacket, err := packet.New(uint64(packetType), packetBytes, strconv.Itoa(mark), true)

		if parsedPacket.IPProto() == packet.IPProtocolUDP && parsedPacket.SourcePort() == 53 {
			// notify PUs of DNS results
			err := d.dnsProxy.HandleDNSResponsePacket(parsedPacket.GetUDPData(), parsedPacket.SourceAddress(), func(id string) (*pucontext.PUContext, error) {
				puCtx, err1 := d.puFromContextID.Get(id)
				if err1 != nil {
					return nil, err1
				}
				return puCtx.(*pucontext.PUContext), nil
			})
			if err != nil {
				zap.L().Error("Failed to handle DNS response", zap.Error(err))
			}
			// forward packet
			err = frontman.Wrapper.PacketFilterForward(&packetInfo, packetBytes)
			if err != nil {
				zap.L().Error("failed to forward packet", zap.Error(err))
			}
			return 0
		}

		parsedPacket.PlatformMetadata = &afinetrawsocket.PacketMetadata{PacketInfo: packetInfo, IgnoreFlow: false}
		var processError error
		var tcpConn *connection.TCPConnection
		var udpConn *connection.UDPConnection
		if err != nil {
			parsedPacket.Print(packet.PacketFailureCreate, d.packetLogs)
		} else if parsedPacket.IPProto() == packet.IPProtocolTCP {
			if packetType == packet.PacketTypeNetwork {
				tcpConn, processError = d.processNetworkTCPPackets(parsedPacket)
			} else {
				tcpConn, processError = d.processApplicationTCPPackets(parsedPacket)
			}
		} else if parsedPacket.IPProto() == packet.IPProtocolUDP {
			// process udp packet
			if packetType == packet.PacketTypeNetwork {
				udpConn, processError = d.ProcessNetworkUDPPacket(parsedPacket)
			} else {
				udpConn, processError = d.ProcessApplicationUDPPacket(parsedPacket)
			}
		} else {
			processError = fmt.Errorf("invalid ip protocol: %d", parsedPacket.IPProto())
		}

		if processError != nil {
			if parsedPacket.IPProto() == packet.IPProtocolTCP {
				d.collectTCPPacket(&debugpacketmessage{
					Mark:    mark,
					p:       parsedPacket,
					tcpConn: tcpConn,
					udpConn: nil,
					err:     processError,
					network: packetType == packet.PacketTypeNetwork,
				})
			} else if parsedPacket.IPProto() == packet.IPProtocolUDP {
				d.collectUDPPacket(&debugpacketmessage{
					Mark:    mark,
					p:       parsedPacket,
					tcpConn: nil,
					udpConn: udpConn,
					err:     processError,
					network: packetType == packet.PacketTypeNetwork,
				})
			}
			// drop packet by not forwarding it
			return 0
		}

		// accept the (modified) packet by forwarding it
		var modifiedPacketBytes []byte
		if parsedPacket.IPProto() == packet.IPProtocolTCP {
			modifiedPacketBytes = make([]byte, parsedPacket.IPTotalLen())
			copyIndex := copy(modifiedPacketBytes, parsedPacket.GetBuffer(0))
			copyIndex += copy(modifiedPacketBytes[copyIndex:], parsedPacket.GetTCPOptions())
			copyIndex += copy(modifiedPacketBytes[copyIndex:], parsedPacket.GetTCPData())
			packetInfo.PacketSize = uint32(copyIndex)
		} else {
			modifiedPacketBytes = parsedPacket.GetBuffer(0)
			packetInfo.PacketSize = uint32(len(modifiedPacketBytes))
		}

		if parsedPacket.PlatformMetadata.(*afinetrawsocket.PacketMetadata).IgnoreFlow {
			packetInfo.IgnoreFlow = 1
		}
		if err := frontman.Wrapper.PacketFilterForward(&packetInfo, modifiedPacketBytes); err != nil {
			zap.L().Error("failed to forward packet", zap.Error(err))
		}

		if parsedPacket.IPProto() == packet.IPProtocolTCP {
			d.collectTCPPacket(&debugpacketmessage{
				Mark:    mark,
				p:       parsedPacket,
				tcpConn: tcpConn,
				udpConn: nil,
				err:     nil,
				network: packetType == packet.PacketTypeNetwork,
			})
		} else if parsedPacket.IPProto() == packet.IPProtocolUDP {
			d.collectUDPPacket(&debugpacketmessage{
				Mark:    mark,
				p:       parsedPacket,
				tcpConn: nil,
				udpConn: udpConn,
				err:     nil,
				network: packetType == packet.PacketTypeNetwork,
			})
		}

		return 0
	}

	logCallback := func(logPacketInfoPtr, dataPtr uintptr) uintptr {

		logPacketInfo := *(*frontman.LogPacketInfo)(unsafe.Pointer(logPacketInfoPtr)) //nolint:govet
		packetHeaderBytes := (*[1 << 30]byte)(unsafe.Pointer(dataPtr))[:logPacketInfo.PacketSize:logPacketInfo.PacketSize]

		err := nflogWin.NfLogHandler(&logPacketInfo, packetHeaderBytes)
		if err != nil {
			zap.L().Error("error in log callback", zap.Error(err))
		}

		return 0
	}

	if err := frontman.Wrapper.PacketFilterStart("Aporeto Enforcer", packetCallback, logCallback); err != nil {
		return err
	}

	return nil
}

// cleanupPlatform for windows is needed to stop the frontman threads and permit the enforcerd app to shut down
func (d *Datapath) cleanupPlatform() {

	if err := frontman.Wrapper.PacketFilterClose(); err != nil {
		zap.L().Error("Failed to close packet proxy", zap.Error(err))
	}

}
