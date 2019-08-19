// +build windows

package nfqdatapath

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"unsafe"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/windatapath"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.uber.org/zap"
)

// #cgo CFLAGS: -I .
//#include ".\windatapath\windivert.h"
import "C"

const (
	//networkFilter = "inbound and ip.SrcAddr=10.128.128.128 and ip.Protocol!=17"
	networkFilter = "inbound and ip.Protocol!=17 and ip.SrcAddr!=172.31.8.191 and tcp.DstPort!=3389"
	appFilter     = "outbound and ip.Protocol!=17 and ip.DstAddr!=172.31.17.191 tcp.SrcPort!=3389"
	//appFilter     = "outbound and ip.DstAddr=10.128.128.128 and ip.Protocol!=17"
)

// startNetworkInterceptor will the process that processes  packets from the network
// Still has one more copy than needed. Can be improved.
func (d *Datapath) startNetworkInterceptor(ctx context.Context) {

	if hdl, err := windatapath.NewWindatapath(); err != nil {
		zap.L().Fatal("Unable to start windatapath", zap.Error(err))
	} else {
		fmt.Println("Network API URL", os.Getenv("APIURL"))
		datapathhdl, err := hdl.WinDivertOpen(networkFilter, 0, 0, 0)
		handleNum := (*int64)(unsafe.Pointer(datapathhdl))
		//zap.L().Error("Network ERROR", zap.Error(err))
		if handleNum == nil {
			zap.L().Error("Not Sucessful")
		}
		//zap.L().Error("Handle Num", zap.Reflect("Vale", datapathhdl))

		if handleNum == nil {
			zap.L().Fatal("Failed to open windivert device", zap.Error(err))
		} else {
			go func() {
				data := make([]byte, 64*1024)

				var packetLen uint
				for {
					packetLen = uint(len(data))
					//zap.L().Error("NETWORK RECEIVING Packet")
					if recvAddr, _ := hdl.WinDivertRecv(datapathhdl, data, &packetLen); recvAddr != nil {
						//zap.L().Error("Network packet", zap.Int("PacketLen", int(packetLen)))
						d.processNetworkPacketsFromWindivert(datapathhdl, hdl, data[:packetLen], recvAddr)
						//zap.L().Debug("packet", zap.String("packet", (hex.Dump(data))))
						continue
					}
					zap.L().Error("Cannot received packets", zap.Error(err)) /*  */

				}
			}()
		}
	}
	return

}

// startApplicationInterceptor will create a interceptor that processes
// packets originated from a local application
func (d *Datapath) startApplicationInterceptor(ctx context.Context) {
	if hdl, err := windatapath.NewWindatapath(); err != nil {
		zap.L().Fatal("Unable to start windatapath", zap.Error(err))
	} else {
		apiURL := os.Getenv("APIURL")
		u, _ := url.Parse(apiURL)

		filter := appFilter
		fmt.Println("application APIURL", u.Host)
		/* if len(apiURL) > 0 {
			if addrs, err := net.LookupHost(u.Host); err == nil {
				for _, addr := range addrs {
					filter += "\"and ip.DstAddr != " + addr + "\""
				}
			} else {
				fmt.Println("API LOOKUP URL error", err)
			}

		} */

		datapathhdl, err := hdl.WinDivertOpen(filter, 0, 0, 0)
		handleNum := (*int64)(unsafe.Pointer(datapathhdl))
		if handleNum == nil {
			zap.L().Error("Not Sucessful")
		}

		if handleNum == nil {
			zap.L().Fatal("Failed to open windivert device", zap.Error(err))
		} else {
			go func() {
				data := make([]byte, 64*1024)
				//recvAddr := windatapth.C.WINDIVERT_ADDRESS{}
				var packetLen uint
				for {
					packetLen = uint(len(data))
					//zap.L().Error("Application RECEIVING Packet")
					if recvAddr, _ := hdl.WinDivertRecv(datapathhdl, data, &packetLen); recvAddr != nil {
						//zap.L().Error("Application packet", zap.Int("Packet Len", int(packetLen)))
						d.processApplicationPacketsFromWinDivert(datapathhdl, hdl, data[:packetLen], recvAddr)
						//zap.L().Error("Application packet processed", zap.Int("Packet Len", int(packetLen)))

						//zap.L().Error(" ", zap.String("packet", hex.Dump(data[:packetLen])))
						continue
					}
					zap.L().Error("Cannot received packets", zap.Error(err))
				}
			}()
		}
	}

}

func (d *Datapath) processApplicationPacketsFromWinDivert(datapathhdl uintptr, windivertHdl windatapath.WinDivertHdl, data []byte, recvAddr unsafe.Pointer) {
	// writeLen := uint(len(data))
	// err := windivertHdl.WinDivertSend(datapathhdl, data, recvAddr, &writeLen)
	// zap.L().Error("Application Send Error", zap.Error(err))
	netPacket, err := packet.New(packet.PacketTypeApplication, data, strconv.Itoa(int(100)), true)

	if err != nil {
		//fmt.Println(hex.Dump(data))
		//fmt.Println("Error", err)
		//netPacket.Print(packet.PacketFailureCreate)
	} else if netPacket.IPProto == packet.IPProtocolTCP {
		err = d.processApplicationTCPPackets(netPacket)
	} else if netPacket.IPProto == packet.IPProtocolUDP {
		err = d.ProcessApplicationUDPPacket(netPacket)
	} else {
		err = fmt.Errorf("invalid ip protocol: %d", netPacket.IPProto)
	}
	if err != nil {
		return
	}

	if netPacket.IPProto == packet.IPProtocolTCP {
		// // Accept the packet
		buffer := make([]byte, len(netPacket.Buffer)+netPacket.TCPOptionLength()+netPacket.TCPDataLength())
		copyIndex := copy(buffer, netPacket.Buffer)
		copyIndex += copy(buffer[copyIndex:], netPacket.GetTCPOptions())
		copyIndex += copy(buffer[copyIndex:], netPacket.GetTCPData())
		writeLen := uint(copyIndex)
		//zap.L().Error("Send The packet", zap.String("packet", string(hex.Dump(buffer[:copyIndex]))))
		err = windivertHdl.WinDivertSend(datapathhdl, buffer, recvAddr, &writeLen)
		//p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), 1, uint32(p.Mark), uint32(copyIndex), uint32(p.ID), buffer)
	} else {
		// Buffer is already modified.
		buffer := make([]byte, len(netPacket.Buffer))
		copyIndex := copy(buffer, netPacket.Buffer)
		writeLen := uint(copyIndex)
		windivertHdl.WinDivertSend(datapathhdl, buffer, recvAddr, &writeLen)
		//p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), 1, uint32(p.Mark), uint32(copyIndex), uint32(p.ID), buffer)

	}

	return
}

func (d *Datapath) processNetworkPacketsFromWindivert(datapathhdl uintptr, windivertHdl windatapath.WinDivertHdl, data []byte, recvAddr unsafe.Pointer) {
	// writeLen := uint(len(data))
	// err := windivertHdl.WinDivertSend(datapathhdl, data, recvAddr, &writeLen)
	// zap.L().Error("Network Send Error", zap.Error(err))
	// Parse the packet - drop if parsing fails
	netPacket, err := packet.New(packet.PacketTypeNetwork, data, strconv.Itoa(int(100)), true)

	if err != nil {
		if netPacket == nil {
			fmt.Println(err)
			return
		}
		netPacket.Print(packet.PacketFailureCreate)
	} else if netPacket.IPProto == packet.IPProtocolTCP {
		err = d.processNetworkTCPPackets(netPacket)
	} else if netPacket.IPProto == packet.IPProtocolUDP {
		err = d.ProcessNetworkUDPPacket(netPacket)
	} else {
		err = fmt.Errorf("invalid ip protocol: %d", netPacket.IPProto)
	}
	if err != nil {
		//zap.L().Error("Network Error", zap.Error(err))
		//p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), 0, uint32(p.Mark), length, uint32(p.ID), buffer)
		return
	}

	if netPacket.IPProto == packet.IPProtocolTCP {
		// // Accept the packet
		buffer := make([]byte, len(netPacket.Buffer)+netPacket.TCPOptionLength()+netPacket.TCPDataLength())
		copyIndex := copy(buffer, netPacket.Buffer)
		copyIndex += copy(buffer[copyIndex:], netPacket.GetTCPOptions())
		copyIndex += copy(buffer[copyIndex:], netPacket.GetTCPData())
		writeLen := uint(copyIndex)
		windivertHdl.WinDivertSend(datapathhdl, buffer, recvAddr, &writeLen)
		//p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), 1, uint32(p.Mark), uint32(copyIndex), uint32(p.ID), buffer)
	} else {
		// Buffer is already modified.
		buffer := make([]byte, len(netPacket.Buffer))
		copyIndex := copy(buffer, netPacket.Buffer)
		writeLen := uint(copyIndex)
		windivertHdl.WinDivertSend(datapathhdl, buffer, recvAddr, &writeLen)
		//p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), 1, uint32(p.Mark), uint32(copyIndex), uint32(p.ID), buffer)

	}
	return
}
