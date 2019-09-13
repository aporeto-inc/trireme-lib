// +build windows

package nfqdatapath

import (
	"context"
	"fmt"
	"strconv"
	"syscall"
	"unsafe"

	"go.aporeto.io/trireme-lib/controller/internal/windows/frontman"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
)

func (d *Datapath) startFrontmanPacketFilter(ctx context.Context) error {
	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return err
	}

	callback := func(proxyPacketPtr, dataPtr uintptr) uintptr {

		proxyPacket := *(*frontman.ProxyPacket)(unsafe.Pointer(proxyPacketPtr))
		packetBytes := make([]byte, proxyPacket.PacketSize)

		ptr := uintptr(unsafe.Pointer(dataPtr))
		for i := uint32(0); i < proxyPacket.PacketSize; i++ {
			packetBytes[i] = *(*byte)(unsafe.Pointer(ptr))
			ptr++
		}

		var packetType int
		if proxyPacket.Outbound != 0 {
			packetType = packet.PacketTypeApplication
		} else {
			packetType = packet.PacketTypeNetwork
		}

		// TODO(windows): temp - for now just forward all packets unmodified
		frontman.PacketFilterForwardProc.Call(proxyPacketPtr, uintptr(unsafe.Pointer(&packetBytes[0])))
		return 0

		// Parse the packet
		mark := int(proxyPacket.Mark) // TODO
		parsedPacket, err := packet.New(uint64(packetType), packetBytes, strconv.Itoa(mark), true)
		var processError error
		var tcpConn *connection.TCPConnection
		//var udpConn *connection.UDPConnection
		if err != nil {
			parsedPacket.Print(packet.PacketFailureCreate, d.packetLogs)
		} else if parsedPacket.IPProto() == packet.IPProtocolTCP {
			if packetType == packet.PacketTypeNetwork {
				tcpConn, processError = d.processNetworkTCPPackets(parsedPacket)
			} else {
				tcpConn, processError = d.processApplicationTCPPackets(parsedPacket)
			}
		} else if parsedPacket.IPProto() == packet.IPProtocolUDP {
			/*if packetType == packet.PacketTypeNetwork {
				udpConn, processError = d.ProcessNetworkUDPPacket(parsedPacket)
			} else {
				udpConn, processError = d.ProcessApplicationUDPPacket(parsedPacket)
			}*/
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
				/*d.collectUDPPacket(&debugpacketmessage{
					Mark:    mark,
					p:       parsedPacket,
					tcpConn: nil,
					udpConn: udpConn,
					err:     processError,
					network: packetType == packet.PacketTypeNetwork,
				})*/
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
			proxyPacket.PacketSize = uint32(copyIndex)
		} else {
			modifiedPacketBytes = parsedPacket.GetBuffer(0)
			proxyPacket.PacketSize = uint32(len(modifiedPacketBytes))
		}

		// proxyPacketPtr still points to correct (modified) struct
		frontman.PacketFilterForwardProc.Call(proxyPacketPtr, uintptr(unsafe.Pointer(&modifiedPacketBytes[0])))

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
			/*d.collectUDPPacket(&debugpacketmessage{
				Mark:    mark,
				p:       parsedPacket,
				tcpConn: nil,
				udpConn: udpConn,
				err:     nil,
				network: packetType == packet.PacketTypeNetwork,
			})*/
		}

		return 0
	}

	dllRet, _, err := frontman.PacketFilterStartProc.Call(driverHandle, syscall.NewCallbackCDecl(callback))
	if dllRet == 0 {
		return fmt.Errorf("%s failed: %v", frontman.PacketFilterStartProc.Name, err)
	}

	return nil
}

// startApplicationInterceptor will create a interceptor that processes
// packets originated from a local application
func (d *Datapath) startApplicationInterceptor(ctx context.Context) {
	// TODO(windows): turn on packet filter here
	//err := d.startFrontmanPacketFilter(ctx)
	//if err != nil {
	//	zap.L().Fatal("Unable to initialize windows packet proxy", zap.Error(err))
	//}
}

// startNetworkInterceptor will the process that processes  packets from the network
func (d *Datapath) startNetworkInterceptor(ctx context.Context) {
	// for Windows, we do nothing here since our packet proxy sends outbound and inbound
	// TODO(windows): cleanup api to make more sense
}
