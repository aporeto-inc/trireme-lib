// +build linux

package nfqdatapath

// Go libraries
import (
	"context"
	"fmt"
	"strconv"

	"go.aporeto.io/trireme-lib/controller/internal/datapathdriver"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.uber.org/zap"
)

func errorCallback(err error, data interface{}) {
	zap.L().Error("Error while processing packets on queue", zap.Error(err))
}
func networkCallback(packet *datapathdriver.Packet, d interface{}) ([]byte, error) {
	return d.(*Datapath).processNetworkPacketsFromNFQ(packet)
}

func appCallBack(packet *datapathdriver.Packet, d interface{}) ([]byte, error) {
	return d.(*Datapath).processApplicationPacketsFromNFQ(packet)
}

// startNetworkInterceptor will the process that processes  packets from the network
// Still has one more copy than needed. Can be improved.
func (d *Datapath) startNetworkInterceptor(ctx context.Context) {
	fqaccessor := fqconfig.NewFilterQueueAccessor(d.filterQueue, "network")
	if err := d.packetDriver.StartPacketProcessor(ctx, fqaccessor, networkCallback, errorCallback, d); err != nil {
		zap.L().Fatal("Cannot start network packet processor", zap.Error(err))
	}
}

// startApplicationInterceptor will create a interceptor that processes
// packets originated from a local application
func (d *Datapath) startApplicationInterceptor(ctx context.Context) {
	fqaccessor := fqconfig.NewFilterQueueAccessor(d.filterQueue, "application")
	if err := d.packetDriver.StartPacketProcessor(ctx, fqaccessor, appCallBack, errorCallback, d); err != nil {
		zap.L().Fatal("Cannot start application packet processor", zap.Error(err))
	}

}

// processNetworkPacketsFromNFQ processes packets arriving from the network in an NF queue
func (d *Datapath) processNetworkPacketsFromNFQ(p *datapathdriver.Packet) ([]byte, error) {

	// Parse the packet - drop if parsing fails
	netPacket, err := packet.New(packet.PacketTypeNetwork, p.Payload(), strconv.Itoa(int(p.Mark())), true)

	if err != nil {
		netPacket.Print(packet.PacketFailureCreate)
	} else if netPacket.IPProto == packet.IPProtocolTCP {
		err = d.processNetworkTCPPackets(netPacket)
	} else if netPacket.IPProto == packet.IPProtocolUDP {
		err = d.ProcessNetworkUDPPacket(netPacket)
	} else {
		return []byte{}, fmt.Errorf("invalid ip protocol: %d", netPacket.IPProto)
	}

	if err != nil {
		return []byte{}, fmt.Errorf("Dropping packet because %s", err)
	}

	if netPacket.IPProto == packet.IPProtocolTCP {
		// Accept the packet
		buffer := make([]byte, len(netPacket.Buffer)+netPacket.TCPOptionLength()+netPacket.TCPDataLength())
		copyIndex := copy(buffer, netPacket.Buffer)
		copyIndex += copy(buffer[copyIndex:], netPacket.GetTCPOptions())
		copyIndex += copy(buffer[copyIndex:], netPacket.GetTCPData())
		return buffer[:copyIndex], nil
	}
	// Buffer is already modified.
	buffer := make([]byte, len(netPacket.Buffer))
	copyIndex := copy(buffer, netPacket.Buffer)
	return buffer[:copyIndex], nil

}

// processApplicationPackets processes packets arriving from an application and are destined to the network
func (d *Datapath) processApplicationPacketsFromNFQ(p *datapathdriver.Packet) ([]byte, error) {

	// Being liberal on what we transmit - malformed TCP packets are let go
	// We are strict on what we accept on the other side, but we don't block
	// lots of things at the ingress to the network
	appPacket, err := packet.New(packet.PacketTypeApplication, p.Payload(), strconv.Itoa(int(p.Mark())), true)

	if err != nil {
		appPacket.Print(packet.PacketFailureCreate)
	} else if appPacket.IPProto == packet.IPProtocolTCP {
		err = d.processApplicationTCPPackets(appPacket)
	} else if appPacket.IPProto == packet.IPProtocolUDP {
		err = d.ProcessApplicationUDPPacket(appPacket)
	} else {
		err = fmt.Errorf("invalid ip protocol: %d", appPacket.IPProto)
	}

	if err != nil {
		return []byte{}, fmt.Errorf("Dropping packet %s", err)
	}

	if appPacket.IPProto == packet.IPProtocolTCP {
		// Accept the packet
		buffer := make([]byte, len(appPacket.Buffer)+appPacket.TCPOptionLength()+appPacket.TCPDataLength())
		copyIndex := copy(buffer, appPacket.Buffer)
		copyIndex += copy(buffer[copyIndex:], appPacket.GetTCPOptions())
		copyIndex += copy(buffer[copyIndex:], appPacket.GetTCPData())

		//p.QueueHandle.SetVerdict2(uint32(p.QueueHandle.QueueNum), 1, uint32(p.Mark), uint32(copyIndex), uint32(p.ID), buffer)
		return buffer[:copyIndex], nil
	}
	buffer := make([]byte, len(appPacket.Buffer))
	copyIndex := copy(buffer, appPacket.Buffer)
	return buffer[:copyIndex], nil

}
