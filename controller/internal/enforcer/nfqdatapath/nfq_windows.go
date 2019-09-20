// +build windows

package nfqdatapath

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"unsafe"

	"go.aporeto.io/trireme-lib/controller/internal/windows/frontman"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.uber.org/zap"
)

func (d *Datapath) startFrontmanPacketFilter(ctx context.Context) error {
	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return err
	}

	callback := func(packetInfoPtr, dataPtr uintptr) uintptr {

		packetInfo := *(*frontman.PacketInfo)(unsafe.Pointer(packetInfoPtr))
		packetBytes := make([]byte, packetInfo.PacketSize)

		ptr := uintptr(unsafe.Pointer(dataPtr))
		for i := uint32(0); i < packetInfo.PacketSize; i++ {
			packetBytes[i] = *(*byte)(unsafe.Pointer(ptr))
			ptr++
		}

		var packetType int
		if packetInfo.Outbound != 0 {
			packetType = packet.PacketTypeApplication
		} else {
			packetType = packet.PacketTypeNetwork
		}

		// TODO(windows): temp
		var localAddr, remoteAddr string
		if packetInfo.Ipv4 != 0 {
			localAddr = net.IPv4(byte(packetInfo.LocalAddr[0]&0xff),
				byte((packetInfo.LocalAddr[0]&0xff00)>>8),
				byte((packetInfo.LocalAddr[0]&0xff0000)>>16),
				byte((packetInfo.LocalAddr[0]&0xff000000)>>24)).String()
			remoteAddr = net.IPv4(byte(packetInfo.RemoteAddr[0]&0xff),
				byte((packetInfo.RemoteAddr[0]&0xff00)>>8),
				byte((packetInfo.RemoteAddr[0]&0xff0000)>>16),
				byte((packetInfo.RemoteAddr[0]&0xff000000)>>24)).String()
		} else {
			localAddr = strconv.Itoa(int(packetInfo.LocalAddr[0])) +
				strconv.Itoa(int(packetInfo.LocalAddr[1])) +
				strconv.Itoa(int(packetInfo.LocalAddr[2])) +
				strconv.Itoa(int(packetInfo.LocalAddr[3]))
			remoteAddr = strconv.Itoa(int(packetInfo.RemoteAddr[0])) +
				strconv.Itoa(int(packetInfo.RemoteAddr[1])) +
				strconv.Itoa(int(packetInfo.RemoteAddr[2])) +
				strconv.Itoa(int(packetInfo.RemoteAddr[3]))
		}
		zap.L().Info(fmt.Sprintf("got packet of size %d and mark %d and outbound is %d with localPort %d and localAddr %v and remotePort %d and remoteAddr %v and other %d %d %d",
			packetInfo.PacketSize, packetInfo.Mark, packetInfo.Outbound, packetInfo.LocalPort, localAddr, packetInfo.RemotePort,
			remoteAddr, packetInfo.Ipv4, packetInfo.Protocol, packetInfo.Outbound))
		//frontman.PacketFilterForwardProc.Call(packetInfoPtr, uintptr(unsafe.Pointer(&packetBytes[0])))
		//return 0

		// Parse the packet
		mark := int(packetInfo.Mark)
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
			zap.L().Error(fmt.Sprintf("Got ERROR: %v", processError))
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
			packetInfo.PacketSize = uint32(copyIndex)
		} else {
			modifiedPacketBytes = parsedPacket.GetBuffer(0)
			packetInfo.PacketSize = uint32(len(modifiedPacketBytes))
		}

		zap.L().Info(fmt.Sprintf("forwarding modified packet of size %d and mark %d", packetInfo.PacketSize, packetInfo.Mark))
		dllRet, _, err := frontman.PacketFilterForwardProc.Call(uintptr(unsafe.Pointer(&packetInfo)), uintptr(unsafe.Pointer(&modifiedPacketBytes[0])))
		if dllRet == 0 {
			zap.L().Error(fmt.Sprintf("%s failed: %v", frontman.PacketFilterForwardProc.Name, err))
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
	err := d.startFrontmanPacketFilter(ctx)
	if err != nil {
		zap.L().Fatal("Unable to initialize windows packet proxy", zap.Error(err))
	}
}

// startNetworkInterceptor will the process that processes  packets from the network
func (d *Datapath) startNetworkInterceptor(ctx context.Context) {
	// for Windows, we do nothing here since our packet proxy sends outbound and inbound
	// TODO(windows): cleanup api to make more sense
}

// cleanupPlatform for windows is needed to stop the frontman threads and permit the enforcerd app to shut down
func (d *Datapath) cleanupPlatform() {
	dllRet, _, err := frontman.PacketFilterCloseProc.Call()
	if dllRet == 0 {
		zap.L().Error("Failed to close packet proxy", zap.Error(err))
	}
}
