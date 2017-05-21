package enforcer

// Go libraries
import (
	"fmt"

	"github.com/aporeto-inc/trireme/enforcer/netfilter"
	"github.com/aporeto-inc/trireme/enforcer/utils/packet"
	"go.uber.org/zap"
)

// startNetworkInterceptor will the process that processes  packets from the network
// Still has one more copy than needed. Can be improved.
func (d *Datapath) startNetworkInterceptor() {
	var err error

	d.netStop = make([]chan bool, d.filterQueue.GetNumNetworkQueues())
	for i := uint16(0); i < d.filterQueue.GetNumNetworkQueues(); i++ {
		d.netStop[i] = make(chan bool)
	}

	nfq := make([]*netfilter.NFQueue, d.filterQueue.GetNumNetworkQueues())

	for i := uint16(0); i < d.filterQueue.GetNumNetworkQueues(); i++ {

		// Initialize all the queues
		nfq[i], err = netfilter.NewNFQueue(d.filterQueue.GetNetworkQueueStart()+i, d.filterQueue.GetNetworkQueueSize(), netfilter.NfDefaultPacketSize)
		if err != nil {
			zap.L().Fatal("Unable to initialize netfilter queue", zap.Error(err))
		}

		go func(j uint16) {
			for {
				select {
				case packet := <-nfq[j].Packets:
					d.processNetworkPacketsFromNFQ(packet)
				case <-d.netStop[j]:
					return
				}
			}
		}(i)

	}
}

// startApplicationInterceptor will create a interceptor that processes
// packets originated from a local application
func (d *Datapath) startApplicationInterceptor() {

	var err error

	d.appStop = make([]chan bool, d.filterQueue.GetNumApplicationQueues())
	for i := uint16(0); i < d.filterQueue.GetNumApplicationQueues(); i++ {
		d.appStop[i] = make(chan bool)
	}

	nfq := make([]*netfilter.NFQueue, d.filterQueue.GetNumApplicationQueues())

	for i := uint16(0); i < d.filterQueue.GetNumApplicationQueues(); i++ {
		nfq[i], err = netfilter.NewNFQueue(d.filterQueue.GetApplicationQueueStart()+i, d.filterQueue.GetApplicationQueueSize(), netfilter.NfDefaultPacketSize)

		if err != nil {
			zap.L().Fatal("Unable to initialize netfilter queue", zap.Error(err))
		}

		go func(j uint16) {
			for {
				select {
				case packet := <-nfq[j].Packets:
					d.processApplicationPacketsFromNFQ(packet)
				case <-d.appStop[j]:
					return
				}
			}
		}(i)
	}
}

// processNetworkPacketsFromNFQ processes packets arriving from the network in an NF queue
func (d *Datapath) processNetworkPacketsFromNFQ(p *netfilter.NFPacket) {

	d.net.IncomingPackets++

	// Parse the packet - drop if parsing fails
	netPacket, err := packet.New(packet.PacketTypeNetwork, p.Buffer, p.Mark)

	if err != nil {
		d.net.CreateDropPackets++
		netPacket.Print(packet.PacketFailureCreate)
	} else if netPacket.IPProto == packet.IPProtocolTCP {
		err = d.processNetworkTCPPackets(netPacket)
	} else {
		d.net.ProtocolDropPackets++
		err = fmt.Errorf("Invalid IP Protocol %d", netPacket.IPProto)
	}

	if err != nil {
		netfilter.SetVerdict(&netfilter.Verdict{
			V:           netfilter.NfDrop,
			Buffer:      netPacket.Buffer,
			Payload:     nil,
			Options:     nil,
			Xbuffer:     p.Xbuffer,
			ID:          p.ID,
			QueueHandle: p.QueueHandle,
		}, d.filterQueue.GetMarkValue())
		return
	}

	// Accept the packet
	netfilter.SetVerdict(&netfilter.Verdict{
		V:           netfilter.NfAccept,
		Buffer:      netPacket.Buffer,
		Payload:     netPacket.GetTCPData(),
		Options:     netPacket.GetTCPOptions(),
		Xbuffer:     p.Xbuffer,
		ID:          p.ID,
		QueueHandle: p.QueueHandle,
	}, d.filterQueue.GetMarkValue())
}

// processApplicationPackets processes packets arriving from an application and are destined to the network
func (d *Datapath) processApplicationPacketsFromNFQ(p *netfilter.NFPacket) {

	d.app.IncomingPackets++

	// Being liberal on what we transmit - malformed TCP packets are let go
	// We are strict on what we accept on the other side, but we don't block
	// lots of things at the ingress to the network
	appPacket, err := packet.New(packet.PacketTypeApplication, p.Buffer, p.Mark)

	if err != nil {
		d.app.CreateDropPackets++
		appPacket.Print(packet.PacketFailureCreate)
	} else if appPacket.IPProto == packet.IPProtocolTCP {
		err = d.processApplicationTCPPackets(appPacket)
	} else {
		d.app.ProtocolDropPackets++
		err = fmt.Errorf("Invalid IP Protocol %d", appPacket.IPProto)
	}

	if err != nil {
		netfilter.SetVerdict(&netfilter.Verdict{
			V:           netfilter.NfDrop,
			Buffer:      appPacket.Buffer,
			Payload:     nil,
			Options:     nil,
			Xbuffer:     p.Xbuffer,
			ID:          p.ID,
			QueueHandle: p.QueueHandle,
		}, d.filterQueue.GetMarkValue())
		return
	}

	// Accept the packet
	netfilter.SetVerdict(&netfilter.Verdict{
		V:           netfilter.NfAccept,
		Buffer:      appPacket.Buffer,
		Payload:     appPacket.GetTCPData(),
		Options:     appPacket.GetTCPOptions(),
		Xbuffer:     p.Xbuffer,
		ID:          p.ID,
		QueueHandle: p.QueueHandle,
	}, d.filterQueue.GetMarkValue())

}
