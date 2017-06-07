package enforcer

import (
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme/enforcer/utils/packetgen"
	"github.com/aporeto-inc/trireme/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme/policy"
	. "github.com/smartystreets/goconvey/convey"
)

var (
	debug          bool
	iteration      int
	TCPFlow        [][]byte
	InvalidTCPFlow [][]byte
	layer          packetgen.PacketFlow
)

func init() {

	debug = true
	iteration = 0

	layer.SrcIPstr = "164.67.228.152"
	layer.DstIPstr = "10.1.10.76"
	ipLayer := layer.GenerateIPPacket(layer.SrcIPstr, layer.DstIPstr)
	layer.SrcPort = 666
	layer.DstPort = 80
	layer.GenerateTCPPacket(&ipLayer, layer.SrcPort, layer.DstPort)
	layer.SetSynTrue()
	layer.SequenceNum = 0
	//layer.InitTemplate()
	TCPFlow = layer.GenerateTCPFlow(layer.TemplateFlow)
	//TCPFlow = layer.GenerateTCPFlowPayload("Aporeto Confidential")

	InvalidTCPFlow = [][]byte{
		{0x45, 0x00, 0x00, 0x40, 0xf4, 0x1f, 0x44, 0x00, 0x40, 0x06, 0xa9, 0x6f, 0x0a, 0x01, 0x0a, 0x4c, 0xa4, 0x43, 0xe4, 0x98, 0xe1, 0xa1, 0x00, 0x50, 0x4d, 0xa6, 0xac, 0x48, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff, 0x6b, 0x6c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x05, 0x01, 0x01, 0x08, 0x0a, 0x1b, 0x4f, 0x37, 0x38, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x4a, 0x1d, 0x70, 0xcf},
	}
}

func TestInvalidContext(t *testing.T) {

	Convey("Given I create a new enforcer instance", t, func() {

		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
		collector := &collector.DefaultCollector{}
		enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.LocalContainer, "/proc").(*Datapath)
		tcpPacket, err := packet.New(0, TCPFlow[0], "0")

		Convey("When I run a TCP Syn packet through a non existing context", func() {

			err1 := enforcer.processApplicationTCPPackets(tcpPacket)
			err2 := enforcer.processNetworkTCPPackets(tcpPacket)

			Convey("Then I should see an error for non existing context", func() {

				So(err, ShouldBeNil)
				So(err1, ShouldNotBeNil)
				So(err2, ShouldNotBeNil)
			})
		})
	})
}

func TestInvalidIPContext(t *testing.T) {

	Convey("Given I create a new enforcer instance", t, func() {

		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
		puInfo := policy.NewPUInfo("SomeProcessingUnitId", constants.ContainerPU)
		collector := &collector.DefaultCollector{}
		enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.LocalContainer, "/proc").(*Datapath)
		enforcer.Enforce("SomeServerId", puInfo) // nolint

		tcpPacket, err := packet.New(0, TCPFlow[0], "0")

		Convey("When I run a TCP Syn packet through an invalid existing context (missing IP)", func() {

			err1 := enforcer.processApplicationTCPPackets(tcpPacket)
			err2 := enforcer.processNetworkTCPPackets(tcpPacket)

			Convey("Then I should see an error for missing IP", func() {

				So(err, ShouldBeNil)
				So(err1, ShouldNotBeNil)
				So(err2, ShouldNotBeNil)
			})
		})
	})
}

func TestInvalidTokenContext(t *testing.T) {

	Convey("Given I create a new enforcer instance", t, func() {

		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
		puInfo := policy.NewPUInfo("SomeProcessingUnitId", constants.ContainerPU)

		ip := policy.NewIPMap(map[string]string{
			"brige": layer.SrcIPstr,
		})
		puInfo.Runtime.SetIPAddresses(ip)
		collector := &collector.DefaultCollector{}
		enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.LocalContainer, "/proc").(*Datapath)
		enforcer.Enforce("SomeServerId", puInfo) // nolint

		tcpPacket, err := packet.New(0, TCPFlow[0], "0")

		Convey("When I run a TCP Syn packet through an invalid existing context (missing token)", func() {

			err1 := enforcer.processApplicationTCPPackets(tcpPacket)
			err2 := enforcer.processNetworkTCPPackets(tcpPacket)

			Convey("Then I should see an error for missing IP", func() {

				So(err, ShouldBeNil)
				So(err1, ShouldNotBeNil)
				So(err2, ShouldNotBeNil)
			})
		})
	})
}

func setupProcessingUnitsInDatapathAndEnforce() (puInfo1, puInfo2 *policy.PUInfo, enforcer *Datapath, err1, err2 error) {

	tagSelector := policy.TagSelector{

		Clause: []policy.KeyValueOperator{
			{
				Key:      TransmitterLabel,
				Value:    []string{"value"},
				Operator: policy.Equal,
			},
		},
		Action: policy.Accept,
	}

	iteration = iteration + 1
	puID1 := "SomeProcessingUnitId" + string(iteration) + "1"
	puID2 := "SomeProcessingUnitId" + string(iteration) + "2"
	puIP1 := layer.SrcIPstr // + strconv.Itoa(iteration)
	puIP2 := layer.DstIPstr // + strconv.Itoa(iteration)
	serverID := "SomeServerId"

	// Create ProcessingUnit 1
	puInfo1 = policy.NewPUInfo(puID1, constants.ContainerPU)

	ip1 := policy.NewIPMap(map[string]string{})
	ip1.Add("bridge", puIP1)
	puInfo1.Runtime.SetIPAddresses(ip1)
	ipl1 := policy.NewIPMap(map[string]string{policy.DefaultNamespace: puIP1})
	puInfo1.Policy.SetIPAddresses(ipl1)
	puInfo1.Policy.AddIdentityTag(TransmitterLabel, "value")
	puInfo1.Policy.AddReceiverRules(&tagSelector)

	// Create processing unit 2
	puInfo2 = policy.NewPUInfo(puID2, constants.ContainerPU)
	ip2 := policy.NewIPMap(map[string]string{"bridge": puIP2})
	puInfo2.Runtime.SetIPAddresses(ip2)
	ipl2 := policy.NewIPMap(map[string]string{policy.DefaultNamespace: puIP2})
	puInfo2.Policy.SetIPAddresses(ipl2)
	puInfo2.Policy.AddIdentityTag(TransmitterLabel, "value")
	puInfo2.Policy.AddReceiverRules(&tagSelector)

	secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))

	collector := &collector.DefaultCollector{}
	enforcer = NewWithDefaults(serverID, collector, nil, secret, constants.LocalContainer, "/proc").(*Datapath)

	err1 = enforcer.Enforce(puID1, puInfo1)

	err2 = enforcer.Enforce(puID2, puInfo2)

	return puInfo1, puInfo2, enforcer, err1, err2
}

func TestPacketHandlingEndToEndPacketsMatch(t *testing.T) {

	SIP := net.IPv4zero
	packetDiffers := false

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {
			puInfo1, puInfo2, enforcer, err1, err2 := setupProcessingUnitsInDatapathAndEnforce()

			So(puInfo1, ShouldNotBeNil)
			So(puInfo2, ShouldNotBeNil)
			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)

			Convey("When I pass multiple packets through the enforcer", func() {

				for i, p := range TCPFlow {

					input := make([]byte, len(p))
					start := make([]byte, len(p))

					copy(input, p)
					copy(start, p)

					oldPacket, err := packet.New(0, start, "0")
					if err == nil && oldPacket != nil {
						oldPacket.UpdateIPChecksum()
						oldPacket.UpdateTCPChecksum()
					}
					tcpPacket, err := packet.New(0, input, "0")
					if err == nil && tcpPacket != nil {
						tcpPacket.UpdateIPChecksum()
						tcpPacket.UpdateTCPChecksum()
					}
					fmt.Println("Print Packet")
					tcpPacket.Print(0)
					if debug {
						fmt.Println("Input packet", i)
						tcpPacket.Print(0)
					}

					So(err, ShouldBeNil)
					So(tcpPacket, ShouldNotBeNil)

					if reflect.DeepEqual(SIP, net.IPv4zero) {
						SIP = tcpPacket.SourceAddress
					}
					if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) &&
						!reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
						t.Error("Invalid Test Packet")
					}

					err = enforcer.processApplicationTCPPackets(tcpPacket)
					if err != nil {
						fmt.Println(err)

					}
					So(err, ShouldBeNil)

					if debug {
						fmt.Println("Intermediate packet", i)
						tcpPacket.Print(0)
					}

					output := make([]byte, len(tcpPacket.GetBytes()))
					copy(output, tcpPacket.GetBytes())

					outPacket, errp := packet.New(0, output, "0")
					So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
					So(errp, ShouldBeNil)
					err = enforcer.processNetworkTCPPackets(outPacket)
					So(err, ShouldBeNil)

					if debug {
						fmt.Println("Output packet", i)
						outPacket.Print(0)
					}

					if !reflect.DeepEqual(oldPacket.GetBytes(), outPacket.GetBytes()) {
						packetDiffers = true
						fmt.Println("Error: packets dont match")
						fmt.Println("Input Packet")
						oldPacket.Print(0)
						fmt.Println("Output Packet")
						outPacket.Print(0)
						t.Errorf("Packet %d Input and output packet do not match", i)
						t.FailNow()
					}
				}

				Convey("Then I expect all the input and output packets (after encoding and decoding) to be same", func() {

					So(packetDiffers, ShouldEqual, false)
				})
			})
		})
	})
}

func TestPacketHandlingFirstThreePacketsHavePayload(t *testing.T) {

	SIP := net.IPv4zero

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {

			puInfo1, puInfo2, enforcer, err1, err2 := setupProcessingUnitsInDatapathAndEnforce()

			So(puInfo1, ShouldNotBeNil)
			So(puInfo2, ShouldNotBeNil)
			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)

			Convey("When I pass multiple packets through the enforcer", func() {

				firstSynAckProcessed := false

				for i, p := range TCPFlow {

					input := make([]byte, len(p))
					start := make([]byte, len(p))

					copy(input, p)
					copy(start, p)

					oldPacket, err := packet.New(0, start, "0")
					if err == nil && oldPacket != nil {
						oldPacket.UpdateIPChecksum()
						oldPacket.UpdateTCPChecksum()
					}
					tcpPacket, err := packet.New(0, input, "0")
					if err == nil && tcpPacket != nil {
						tcpPacket.UpdateIPChecksum()
						tcpPacket.UpdateTCPChecksum()
					}
					if debug {
						fmt.Println("Input packet", i)
						tcpPacket.Print(0)
					}

					So(err, ShouldBeNil)
					So(tcpPacket, ShouldNotBeNil)

					if reflect.DeepEqual(SIP, net.IPv4zero) {
						SIP = tcpPacket.SourceAddress
					}
					if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) &&
						!reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
						t.Error("Invalid Test Packet")
					}

					err = enforcer.processApplicationTCPPackets(tcpPacket)
					So(err, ShouldBeNil)

					if debug {
						fmt.Println("Intermediate packet", i)
						tcpPacket.Print(0)
					}

					if tcpPacket.TCPFlags&packet.TCPSynMask != 0 {
						Convey("When I pass a packet with SYN or SYN/ACK flags for packet "+string(i), func() {
							Convey("Then I expect some data payload to exist on the packet "+string(i), func() {
								// In our 3 way security handshake syn and syn-ack packet should grow in length
								So(tcpPacket.IPTotalLength, ShouldBeGreaterThan, oldPacket.IPTotalLength)
							})
						})
					}

					if !firstSynAckProcessed && tcpPacket.TCPFlags&packet.TCPSynAckMask == packet.TCPAckMask {
						firstSynAckProcessed = true
						Convey("When I pass the first packet with ACK flag for packet "+string(i), func() {
							Convey("Then I expect some data payload to exist on the packet "+string(i), func() {
								// In our 3 way security handshake first ack packet should grow in length
								So(tcpPacket.IPTotalLength, ShouldBeGreaterThan, oldPacket.IPTotalLength)
							})
						})
					}

					output := make([]byte, len(tcpPacket.GetBytes()))
					copy(output, tcpPacket.GetBytes())

					outPacket, errp := packet.New(0, output, "0")
					So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
					So(errp, ShouldBeNil)
					err = enforcer.processNetworkTCPPackets(outPacket)
					So(err, ShouldBeNil)

					if debug {
						fmt.Println("Output packet", i)
						outPacket.Print(0)
					}
				}
			})
		})
	})
}

func TestPacketHandlingDstPortCacheBehavior(t *testing.T) {

	SIP := net.IPv4zero

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {

			puInfo1, puInfo2, enforcer, err1, err2 := setupProcessingUnitsInDatapathAndEnforce()

			So(puInfo1, ShouldNotBeNil)
			So(puInfo2, ShouldNotBeNil)
			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)

			Convey("When I pass multiple packets through the enforcer", func() {

				for i, p := range TCPFlow {

					input := make([]byte, len(p))
					start := make([]byte, len(p))

					copy(input, p)
					copy(start, p)

					oldPacket, err := packet.New(0, start, "0")
					if err == nil && oldPacket != nil {
						oldPacket.UpdateIPChecksum()
						oldPacket.UpdateTCPChecksum()
					}
					tcpPacket, err := packet.New(0, input, "0")
					if err == nil && tcpPacket != nil {
						tcpPacket.UpdateIPChecksum()
						tcpPacket.UpdateTCPChecksum()
					}
					if debug {
						fmt.Println("Input packet", i)
						tcpPacket.Print(0)
					}

					So(err, ShouldBeNil)
					So(tcpPacket, ShouldNotBeNil)

					if reflect.DeepEqual(SIP, net.IPv4zero) {
						SIP = tcpPacket.SourceAddress
					}
					if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) &&
						!reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
						t.Error("Invalid Test Packet")
					}

					err = enforcer.processApplicationTCPPackets(tcpPacket)
					So(err, ShouldBeNil)

					if debug {
						fmt.Println("Intermediate packet", i)
						tcpPacket.Print(0)
					}

					output := make([]byte, len(tcpPacket.GetBytes()))
					copy(output, tcpPacket.GetBytes())

					outPacket, errp := packet.New(0, output, "0")
					So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
					So(errp, ShouldBeNil)
					err = enforcer.processNetworkTCPPackets(outPacket)
					So(err, ShouldBeNil)

					if debug {
						fmt.Println("Output packet", i)
						outPacket.Print(0)
					}
				}
			})
		})
	})
}

func TestConnectionTrackerStateLocalContainer(t *testing.T) {
	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {
		Convey("Given I create a two processing unit instances", func() {
			puInfo1, puInfo2, enforcer, err1, err2 := setupProcessingUnitsInDatapathAndEnforce()

			So(puInfo1, ShouldNotBeNil)
			So(puInfo2, ShouldNotBeNil)
			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
			i := 0 /*first packet in TCPFLOW slice is a syn packet*/
			Convey("When i pass a syn packet through the enforcer", func() {
				packetSlice := selectPacket(i, t)
				tcpPacket := packetSlice[1]
				err := enforcer.processApplicationTCPPackets(tcpPacket)
				//After sending syn packet
				CheckAfterAppSynPacket(enforcer, tcpPacket)
				So(err, ShouldBeNil)
				output := make([]byte, len(tcpPacket.GetBytes()))
				copy(output, tcpPacket.GetBytes())

				outPacket, err := packet.New(0, output, "0")
				So(err, ShouldBeNil)
				err = enforcer.processNetworkTCPPackets(outPacket)
				So(err, ShouldBeNil)
				//Check after processing networksyn packet
				CheckAfterNetSynPacket(enforcer, tcpPacket, outPacket)

			})
			Convey("When i pass a SYN and SYN ACK packet through the enforcer", func() {
				i := 0
				tcpPacket := selectPacket(i, t)[1]
				err := enforcer.processApplicationTCPPackets(tcpPacket)
				So(err, ShouldBeNil)

				output := make([]byte, len(tcpPacket.GetBytes()))
				copy(output, tcpPacket.GetBytes())

				outPacket, err := packet.New(0, output, "0")
				So(err, ShouldBeNil)
				outPacket.Print(0)
				err = enforcer.processNetworkTCPPackets(outPacket)
				So(err, ShouldBeNil)

				//Now lets send the synack packet from the server in response
				i++
				tcpPacket = selectPacket(i, t)[1]
				err = enforcer.processApplicationTCPPackets(tcpPacket)
				So(err, ShouldBeNil)

				output = make([]byte, len(tcpPacket.GetBytes()))
				copy(output, tcpPacket.GetBytes())

				outPacket, err = packet.New(0, output, "0")
				So(err, ShouldBeNil)
				outPacketcopy, _ := packet.New(0, output, "0")
				err = enforcer.processNetworkTCPPackets(outPacket)
				So(err, ShouldBeNil)

				CheckAfterNetSynAckPacket(t, enforcer, outPacketcopy, outPacket)

			})

			Convey("When i pass a SYN and SYNACK and another ACK packet through the enforcer", func() {
				i := 0
				tcpPacket := selectPacket(i, t)[1]
				err := enforcer.processApplicationTCPPackets(tcpPacket)
				So(err, ShouldBeNil)

				output := make([]byte, len(tcpPacket.GetBytes()))
				copy(output, tcpPacket.GetBytes())

				outPacket, err := packet.New(0, output, "0")
				So(err, ShouldBeNil)
				err = enforcer.processNetworkTCPPackets(outPacket)
				So(err, ShouldBeNil)

				//Now lets send the synack packet from the server in response
				i++
				tcpPacket = selectPacket(i, t)[1]
				err = enforcer.processApplicationTCPPackets(tcpPacket)
				So(err, ShouldBeNil)

				output = make([]byte, len(tcpPacket.GetBytes()))
				copy(output, tcpPacket.GetBytes())

				outPacket, err = packet.New(0, output, "0")
				So(err, ShouldBeNil)
				err = enforcer.processNetworkTCPPackets(outPacket)
				So(err, ShouldBeNil)
				i++
				tcpPacket = selectPacket(i, t)[1]
				err = enforcer.processApplicationTCPPackets(tcpPacket)
				CheckAfterAppAckPacket(enforcer, tcpPacket)
				So(err, ShouldBeNil)
				output = make([]byte, len(tcpPacket.GetBytes()))
				copy(output, tcpPacket.GetBytes())

				outPacket, err = packet.New(0, output, "0")
				So(err, ShouldBeNil)
				CheckBeforeNetAckPacket(enforcer, tcpPacket, outPacket)
				err = enforcer.processNetworkTCPPackets(outPacket)
				So(err, ShouldBeNil)

			})
		})
	})
}

func CheckAfterAppSynPacket(enforcer *Datapath, tcpPacket *packet.Packet) {
	appConn, err := enforcer.appOrigConnectionTracker.Get(tcpPacket.L4FlowHash())
	So(appConn.(*TCPConnection).GetState(), ShouldEqual, TCPSynSend)
	So(err, ShouldBeNil)

}

func CheckAfterNetSynPacket(enforcer *Datapath, tcpPacket, outPacket *packet.Packet) {

	appConn, err := enforcer.netOrigConnectionTracker.Get(tcpPacket.L4FlowHash())
	So(err, ShouldBeNil)
	So(appConn.(*TCPConnection).GetState(), ShouldEqual, TCPSynReceived)

}

func CheckAfterNetSynAckPacket(t *testing.T, enforcer *Datapath, tcpPacket, outPacket *packet.Packet) {
	tcpData := tcpPacket.ReadTCPData()
	claims, _, _, nerr := enforcer.tokenEngine.Decode(false, tcpData, nil)
	So(nerr, ShouldBeNil)
	netconn, err := enforcer.sourcePortConnectionCache.Get(outPacket.SourcePortHash(packet.PacketTypeNetwork))
	So(err, ShouldBeNil)
	So(netconn.(*TCPConnection).GetState(), ShouldEqual, TCPSynAckReceived)
	if !reflect.DeepEqual(netconn.(*TCPConnection).Auth.LocalContext, claims.RMT) {
		t.Error("Token parsing Failed")
	}
}

func CheckAfterAppAckPacket(enforcer *Datapath, tcpPacket *packet.Packet) {
	appConn, err := enforcer.appOrigConnectionTracker.Get(tcpPacket.L4FlowHash())
	So(err, ShouldBeNil)
	So(appConn.(*TCPConnection).GetState(), ShouldEqual, TCPAckSend)
}

func CheckBeforeNetAckPacket(enforcer *Datapath, tcpPacket, outPacket *packet.Packet) {

	appConn, err := enforcer.netOrigConnectionTracker.Get(tcpPacket.L4FlowHash())
	So(err, ShouldBeNil)
	So(appConn.(*TCPConnection).GetState(), ShouldEqual, TCPSynAckSend)

}

func TestPacketHandlingSrcPortCacheBehavior(t *testing.T) {

	SIP := net.IPv4zero

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {

			puInfo1, puInfo2, enforcer, err1, err2 := setupProcessingUnitsInDatapathAndEnforce()

			So(puInfo1, ShouldNotBeNil)
			So(puInfo2, ShouldNotBeNil)
			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)

			Convey("When I pass multiple packets through the enforcer", func() {

				firstAckPacketReceived := false

				for i, p := range TCPFlow {

					input := make([]byte, len(p))
					start := make([]byte, len(p))

					copy(input, p)
					copy(start, p)

					oldPacket, err := packet.New(0, start, "0")
					if err == nil && oldPacket != nil {
						oldPacket.UpdateIPChecksum()
						oldPacket.UpdateTCPChecksum()
					}
					tcpPacket, err := packet.New(0, input, "0")
					if err == nil && tcpPacket != nil {
						tcpPacket.UpdateIPChecksum()
						tcpPacket.UpdateTCPChecksum()
					}
					if debug {
						fmt.Println("Input packet", i)
						tcpPacket.Print(0)
					}

					So(err, ShouldBeNil)
					So(tcpPacket, ShouldNotBeNil)

					if reflect.DeepEqual(SIP, net.IPv4zero) {
						SIP = tcpPacket.SourceAddress
					}
					if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) &&
						!reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
						t.Error("Invalid Test Packet")
					}

					err = enforcer.processApplicationTCPPackets(tcpPacket)
					So(err, ShouldBeNil)

					if debug {
						fmt.Println("Intermediate packet", i)
						tcpPacket.Print(0)
					}

					if reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
						// SYN Packets only
						if tcpPacket.TCPFlags&packet.TCPSynAckMask == packet.TCPSynMask {
							Convey("When I pass an application packet with SYN flag for packet "+string(i), func() {
								Convey("Then I expect src port cache to be populated "+string(i), func() {
									fmt.Println("SrcPortHash:" + tcpPacket.SourcePortHash(packet.PacketTypeApplication))
									cs, es := enforcer.sourcePortConnectionCache.Get(tcpPacket.SourcePortHash(packet.PacketTypeApplication))
									So(cs, ShouldNotBeNil)
									So(es, ShouldBeNil)
								})
							})
						}

						// ACK Packets only
						if tcpPacket.TCPFlags&packet.TCPSynAckMask == packet.TCPAckMask {
							if !firstAckPacketReceived {
								firstAckPacketReceived = true
							} else {
								Convey("When I pass any application packets with ACK flag for packet "+string(i), func() {
									Convey("Then I expect src port cache to be NOT populated "+string(i), func() {
										fmt.Println("SrcPortHash:" + tcpPacket.SourcePortHash(packet.PacketTypeApplication))
										cs, es := enforcer.sourcePortConnectionCache.Get(tcpPacket.SourcePortHash(packet.PacketTypeApplication))
										So(cs, ShouldBeNil)
										So(es, ShouldNotBeNil)
									})
								})
							}
						}
					}

					output := make([]byte, len(tcpPacket.GetBytes()))
					copy(output, tcpPacket.GetBytes())

					outPacket, errp := packet.New(0, output, "0")
					So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
					So(errp, ShouldBeNil)
					err = enforcer.processNetworkTCPPackets(outPacket)
					So(err, ShouldBeNil)

					if debug {
						fmt.Println("Output packet", i)
						outPacket.Print(0)
					}

					if reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) {
						if outPacket.TCPFlags&packet.TCPSynAckMask == packet.TCPSynAckMask {
							Convey("When I pass a network packet with SYN/ACK flag for packet "+string(i), func() {
								Convey("Then I expect src port cache to be populated "+string(i), func() {
									cs, es := enforcer.sourcePortConnectionCache.Get(outPacket.SourcePortHash(packet.PacketTypeNetwork))
									So(cs, ShouldNotBeNil)
									So(es, ShouldBeNil)
								})
							})
						}
					}
				}
			})
		})
	})
}

func TestCacheState(t *testing.T) {

	secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
	collector := &collector.DefaultCollector{}
	enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.LocalContainer, "/proc").(*Datapath)
	contextID := "123"

	puInfo := policy.NewPUInfo(contextID, constants.ContainerPU)

	// Should fail: Not in cache
	err := enforcer.Unenforce(contextID)
	if err == nil {
		t.Errorf("Expected failure, no contextID in cache")
	}

	ip := policy.NewIPMap(map[string]string{"bridge": "127.0.0.1"})
	puInfo.Runtime.SetIPAddresses(ip)
	ipl := policy.NewIPMap(map[string]string{"bridge": "127.0.0.1"})
	puInfo.Policy.SetIPAddresses(ipl)

	// Should  not fail:  IP is valid
	err = enforcer.Enforce(contextID, puInfo)
	if err != nil {
		t.Errorf("Expected no failure %s", err)
	}

	// Should  not fail:  Update
	err = enforcer.Enforce(contextID, puInfo)
	if err != nil {
		t.Errorf("Expected no failure %s", err)
	}

	// Should  not fail:  IP is valid
	err = enforcer.Unenforce(contextID)
	if err != nil {
		t.Errorf("Expected failure, no IP but passed %s", err)
	}
}

func TestDoCreatePU(t *testing.T) {

	Convey("Given an initialized enforcer for Linux Processes", t, func() {
		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
		collector := &collector.DefaultCollector{}
		enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.LocalContainer, "/proc").(*Datapath)
		enforcer.mode = constants.LocalServer
		contextID := "123"
		puInfo := policy.NewPUInfo(contextID, constants.LinuxProcessPU)
		tags := &policy.TagsMap{}
		tags.Tags = map[string]string{cgnetcls.CgroupMarkTag: "100", cgnetcls.PortTag: "80,90,100"}
		puInfo.Runtime.SetOptions(tags)
		Convey("When I create a new PU", func() {
			err := enforcer.doCreatePU(contextID, puInfo)

			Convey("It should succeed", func() {
				So(err, ShouldBeNil)
				_, err := enforcer.contextTracker.Get(contextID)
				So(err, ShouldBeNil)
				_, err1 := enforcer.puFromMark.Get("100")
				So(err1, ShouldBeNil)
				_, err2 := enforcer.puFromPort.Get("80")
				So(err2, ShouldBeNil)
				_, err3 := enforcer.puFromPort.Get("90")
				So(err3, ShouldBeNil)
				_, err4 := enforcer.puFromIP.Get(DefaultNetwork)
				So(err4, ShouldNotBeNil)
			})
		})
	})

	Convey("Given an initialized enforcer for Linux Processes", t, func() {
		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
		collector := &collector.DefaultCollector{}
		enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.LocalContainer, "/proc").(*Datapath)
		enforcer.mode = constants.LocalServer
		contextID := "123"
		puInfo := policy.NewPUInfo(contextID, constants.LinuxProcessPU)

		Convey("When I create a new PU without ports or mark", func() {
			err := enforcer.doCreatePU(contextID, puInfo)

			Convey("It should succeed", func() {
				So(err, ShouldBeNil)
				_, err := enforcer.contextTracker.Get(contextID)
				So(err, ShouldBeNil)
				_, err4 := enforcer.puFromIP.Get(DefaultNetwork)
				So(err4, ShouldNotBeNil)
			})
		})
	})

	Convey("Given an initialized enforcer for local Linux Containers", t, func() {
		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
		collector := &collector.DefaultCollector{}
		enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.LocalContainer, "/proc").(*Datapath)

		contextID := "123"
		puInfo := policy.NewPUInfo(contextID, constants.ContainerPU)

		Convey("When I create a new PU without an IP", func() {
			err := enforcer.doCreatePU(contextID, puInfo)

			Convey("It should fail ", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I create a new PU with an IP", func() {
			ip := policy.NewIPMap(map[string]string{
				"bridge": layer.SrcIPstr,
			})
			puInfo.Runtime.SetIPAddresses(ip)
			err := enforcer.doCreatePU(contextID, puInfo)

			Convey("It should succeed ", func() {
				So(err, ShouldBeNil)
				_, err2 := enforcer.puFromIP.Get(layer.SrcIPstr)
				So(err2, ShouldBeNil)
			})
		})
	})

	Convey("Given an initialized enforcer for remote Linux Containers", t, func() {
		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
		collector := &collector.DefaultCollector{}
		enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.LocalContainer, "/proc").(*Datapath)
		enforcer.mode = constants.RemoteContainer

		contextID := "123"
		puInfo := policy.NewPUInfo(contextID, constants.ContainerPU)

		Convey("When I create a new PU without an IP", func() {
			err := enforcer.doCreatePU(contextID, puInfo)

			Convey("It should succeed ", func() {
				So(err, ShouldBeNil)
				_, err2 := enforcer.puFromIP.Get(DefaultNetwork)
				So(err2, ShouldBeNil)
			})
		})
	})
}

func TestContextFromIP(t *testing.T) {

	Convey("Given an initialized enforcer for Linux Processes", t, func() {
		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
		collector := &collector.DefaultCollector{}
		enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.LocalContainer, "/proc").(*Datapath)

		context := &PUContext{
			ID: "SomePU",
			IP: "10.1.1.1",
		}

		Convey("If I try to get the context based on the PU IP, it should succeed ", func() {
			enforcer.puFromIP.AddOrUpdate("10.1.1.1", context)

			ctx, err := enforcer.contextFromIP(true, "10.1.1.1", "", "")
			So(err, ShouldBeNil)
			So(ctx, ShouldNotBeNil)
			So(ctx, ShouldEqual, context)
		})

		Convey("If I try to get context based on IP and its  not there and its a local container it should fail ", func() {
			_, err := enforcer.contextFromIP(true, "20.1.1.1", "", "")
			So(err, ShouldNotBeNil)
		})

		Convey("If I try to get context based on IP and a remote container, it should try the default ", func() {
			enforcer.puFromIP.AddOrUpdate(DefaultNetwork, context)
			enforcer.mode = constants.LocalServer

			ctx, err := enforcer.contextFromIP(true, "20.1.1.1", "", "")
			So(err, ShouldBeNil)
			So(ctx, ShouldNotBeNil)
			So(ctx, ShouldEqual, context)
		})

		Convey("If there is no IP match, it should try the mark for app packets ", func() {
			enforcer.puFromMark.AddOrUpdate("100", context)
			enforcer.mode = constants.LocalServer

			Convey("If the mark exists", func() {
				ctx, err := enforcer.contextFromIP(true, "20.1.1.1", "100", "")
				So(err, ShouldBeNil)
				So(ctx, ShouldNotBeNil)
				So(ctx, ShouldEqual, context)
			})

			Convey("If the mark doesn't exist", func() {
				_, err := enforcer.contextFromIP(true, "20.1.1.1", "2000", "")
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If there is no IP match, it should try the port for net packets ", func() {
			enforcer.puFromPort.AddOrUpdate("8000", context)
			enforcer.mode = constants.LocalServer

			Convey("If the port exists", func() {
				ctx, err := enforcer.contextFromIP(false, "20.1.1.1", "", "8000")
				So(err, ShouldBeNil)
				So(ctx, ShouldNotBeNil)
				So(ctx, ShouldEqual, context)
			})

			Convey("If the port doesn't exist", func() {
				_, err := enforcer.contextFromIP(false, "20.1.1.1", "", "9000")
				So(err, ShouldNotBeNil)
			})
		})

	})
}

func TestInvalidPacket(t *testing.T) {
	// collector := &collector.DefaultCollector{}
	// secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
	// enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.LocalContainer, "/proc").(*Datapath)

	Convey("When I receive an invalid packet", t, func() {
		puInfo1, puInfo2, enforcer, err1, err2 := setupProcessingUnitsInDatapathAndEnforce()

		So(puInfo1, ShouldNotBeNil)
		So(puInfo2, ShouldNotBeNil)
		So(err1, ShouldBeNil)
		So(err2, ShouldBeNil)

		for _, p := range InvalidTCPFlow {
			tcpPacket, err := packet.New(0, p, "0")
			So(err, ShouldBeNil)
			err = enforcer.processApplicationTCPPackets(tcpPacket)
			So(err, ShouldBeNil)
			output := make([]byte, len(tcpPacket.GetBytes()))
			copy(output, tcpPacket.GetBytes())
			outpacket, err := packet.New(0, output, "0")
			So(err, ShouldBeNil)
			//Detach the data and parse token should fail
			err = outpacket.TCPDataDetach(binary.BigEndian.Uint16([]byte{0x0, p[32]})/4 - 20)
			So(err, ShouldBeNil)
			err = enforcer.processNetworkTCPPackets(outpacket)
			So(err, ShouldNotBeNil)
		}
	})
}

func selectPacket(i int, t *testing.T) [2]*packet.Packet {
	input := make([]byte, len(TCPFlow[i]))
	start := make([]byte, len(TCPFlow[i]))
	copy(input, TCPFlow[i])
	copy(start, TCPFlow[i])
	oldPacket, err := packet.New(0, start, "0")
	if err == nil && oldPacket != nil {
		oldPacket.UpdateIPChecksum()
		oldPacket.UpdateTCPChecksum()
	}
	tcpPacket, err := packet.New(0, input, "0")
	if err == nil && tcpPacket != nil {
		tcpPacket.UpdateIPChecksum()
		tcpPacket.UpdateTCPChecksum()
	}
	if debug {
		fmt.Println("Input packet", i)
		tcpPacket.Print(0)
	}

	So(err, ShouldBeNil)
	So(tcpPacket, ShouldNotBeNil)
	SIP := tcpPacket.SourceAddress
	if reflect.DeepEqual(SIP, net.IPv4zero) {
		SIP = tcpPacket.SourceAddress
	}
	if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) &&
		!reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
		t.Error("Invalid Test Packet")
	}
	return [2](*packet.Packet){oldPacket, tcpPacket}
}
