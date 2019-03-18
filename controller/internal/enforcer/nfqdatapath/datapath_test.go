package nfqdatapath

import (
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/aporeto-inc/go-ipset/ipset"
	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/collector/mockcollector"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	enforcerconstants "go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/packetgen"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/packettracing"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/portspec"
)

const (
	testSrcIP    = "10.1.10.76"
	testDstIP    = "164.67.228.152"
	testServerID = "SomeServerId"
)

var (
	debug     bool
	iteration int
)

func setupProcessingUnitsInDatapathAndEnforce(collectors *mockcollector.MockEventCollector, modeType string, targetNetExternal bool) (puInfo1, puInfo2 *policy.PUInfo, enforcer *Datapath, err1, err2, err3, err4 error) {
	var mode constants.ModeType
	if modeType == "container" {
		mode = constants.RemoteContainer
	} else if modeType == "server" {
		mode = constants.LocalServer
	}

	tagSelector := policy.TagSelector{

		Clause: []policy.KeyValueOperator{
			{
				Key:      enforcerconstants.TransmitterLabel,
				Value:    []string{"value"},
				Operator: policy.Equal,
			},
		},
		Policy: &policy.FlowPolicy{Action: policy.Accept},
	}
	PacketFlow := packetgen.NewTemplateFlow()
	_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
	So(err, ShouldBeNil)
	iteration = iteration + 1
	puID1 := "SomeProcessingUnitId" + string(iteration) + "1"
	puID2 := "SomeProcessingUnitId" + string(iteration) + "2"
	puIP1 := PacketFlow.GetNthPacket(0).GetIPPacket().SrcIP.String() // + strconv.Itoa(iteration)
	puIP2 := PacketFlow.GetNthPacket(0).GetIPPacket().DstIP.String() // + strconv.Itoa(iteration)
	serverID := testServerID

	// Create ProcessingUnit 1
	puInfo1 = policy.NewPUInfo(puID1, common.ContainerPU)

	ip1 := policy.ExtendedMap{}
	ip1["bridge"] = puIP1
	puInfo1.Runtime.SetIPAddresses(ip1)
	ipl1 := policy.ExtendedMap{policy.DefaultNamespace: puIP1}
	puInfo1.Policy.SetIPAddresses(ipl1)
	puInfo1.Policy.AddIdentityTag(enforcerconstants.TransmitterLabel, "value")
	puInfo1.Policy.AddReceiverRules(tagSelector)

	// Create processing unit 2
	puInfo2 = policy.NewPUInfo(puID2, common.ContainerPU)

	ip2 := policy.ExtendedMap{"bridge": puIP2}
	puInfo2.Runtime.SetIPAddresses(ip2)
	ipl2 := policy.ExtendedMap{policy.DefaultNamespace: puIP2}
	puInfo2.Policy.SetIPAddresses(ipl2)
	puInfo2.Policy.AddIdentityTag(enforcerconstants.TransmitterLabel, "value")
	puInfo2.Policy.AddReceiverRules(tagSelector)

	secret, err := secrets.NewCompactPKI([]byte(secrets.PrivateKeyPEM), []byte(secrets.PublicPEM), []byte(secrets.CAPEM), secrets.CreateTxtToken(), claimsheader.CompressionTypeNone)
	So(err, ShouldBeNil)
	if collectors != nil {
		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}
		if targetNetExternal {
			enforcer = NewWithDefaults(serverID, collectors, nil, secret, mode, "/proc", []string{"1.1.1.1/31"})
		} else {
			enforcer = NewWithDefaults(serverID, collectors, nil, secret, mode, "/proc", []string{"0.0.0.0/0"})
		}
		enforcer.packetLogs = true
		err1 = enforcer.Enforce(puID1, puInfo1)
		err2 = enforcer.Enforce(puID2, puInfo2)
	} else {
		collector := &collector.DefaultCollector{}
		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		if targetNetExternal {
			enforcer = NewWithDefaults(serverID, collector, nil, secret, mode, "/proc", []string{"1.1.1.1/31"})
		} else {
			enforcer = NewWithDefaults(serverID, collector, nil, secret, mode, "/proc", []string{"0.0.0.0/0"})
		}
		enforcer.packetLogs = true
		err1 = enforcer.Enforce(puID1, puInfo1)
		err2 = enforcer.Enforce(puID2, puInfo2)
	}

	return puInfo1, puInfo2, enforcer, err1, err2, nil, nil
}

func TestEnforcerExternalNetworks(t *testing.T) {
	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {
		var enforcer *Datapath
		var err1, err2 error
		Convey("Given I create a two processing unit instances", func() {
			_, _, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, "container", true)
			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)

			Convey("If I send a syn tcp packet from PU to an ip not in target networks", func() {
				PacketFlow := packetgen.NewTemplateFlow()
				_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
				So(err, ShouldBeNil)

				synPacket, err := PacketFlow.GetFirstSynPacket().ToBytes()
				So(err, ShouldBeNil)

				tcpPacket, err := packet.New(0, synPacket, "0", true)
				if err == nil && tcpPacket != nil {
					tcpPacket.UpdateIPChecksum()
					tcpPacket.UpdateTCPChecksum()
				}
				_, err1 := enforcer.processApplicationTCPPackets(tcpPacket)
				So(err1, ShouldNotBeNil)
			})

		})
		Convey("If I send synack to external network IP in non target network then it should be accepted", func() {
			_, _, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, "container", true)
			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)

			iprules := policy.IPRuleList{policy.IPRule{
				Addresses: []string{"10.1.10.76/32"},
				Ports:     []string{"80"},
				Protocols: []string{constants.TCPProtoNum},
				Policy: &policy.FlowPolicy{
					Action:   policy.Accept,
					PolicyID: "tcp172/8"},
			}}

			contextID := "123456"
			puInfo := policy.NewPUInfo(contextID, common.LinuxProcessPU)
			context, err := pucontext.NewPU(contextID, puInfo, 10*time.Second)
			So(err, ShouldBeNil)
			enforcer.puFromContextID.AddOrUpdate(contextID, context)
			s, _ := portspec.NewPortSpec(80, 80, contextID)
			enforcer.contextIDFromTCPPort.AddPortSpec(s)

			err = context.UpdateNetworkACLs(iprules)
			So(err, ShouldBeNil)

			PacketFlow := packetgen.NewTemplateFlow()

			_, err = PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
			So(err, ShouldBeNil)

			synackPacket, err := PacketFlow.GetFirstSynAckPacket().ToBytes()
			So(err, ShouldBeNil)

			tcpPacket, _ := packet.New(0, synackPacket, "0", true)
			_, err1 := enforcer.processApplicationTCPPackets(tcpPacket)
			So(err1, ShouldBeNil)
		})
	})
}

func TestInvalidContext(t *testing.T) {

	Convey("Given I create a new enforcer instance", t, func() {

		secret, err := secrets.NewCompactPKI([]byte(secrets.PrivateKeyPEM), []byte(secrets.PublicPEM), []byte(secrets.CAPEM), secrets.CreateTxtToken(), claimsheader.CompressionTypeNone)
		So(err, ShouldBeNil)
		collector := &collector.DefaultCollector{}

		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		enforcer := NewWithDefaults(testServerID, collector, nil, secret, constants.LocalServer, "/proc", []string{"0.0.0.0/0"})
		enforcer.packetLogs = true
		PacketFlow := packetgen.NewTemplateFlow()
		_, err = PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
		So(err, ShouldBeNil)
		synPacket, err := PacketFlow.GetFirstSynPacket().ToBytes()
		So(err, ShouldBeNil)
		tcpPacket, err := packet.New(0, synPacket, "0", true)
		Convey("When I run a TCP Syn packet through a non existing context", func() {

			_, err1 := enforcer.processApplicationTCPPackets(tcpPacket)
			_, err2 := enforcer.processNetworkTCPPackets(tcpPacket)

			Convey("Then I should see an error for non existing context", func() {

				So(err, ShouldBeNil)
				So(err1, ShouldNotBeNil)
				So(err2, ShouldBeNil)
			})
		})
	})
}

func TestInvalidIPContext(t *testing.T) {

	Convey("Given I create a new enforcer instance", t, func() {

		secret, err := secrets.NewCompactPKI([]byte(secrets.PrivateKeyPEM), []byte(secrets.PublicPEM), []byte(secrets.CAPEM), secrets.CreateTxtToken(), claimsheader.CompressionTypeNone)
		So(err, ShouldBeNil)
		puInfo := policy.NewPUInfo("SomeProcessingUnitId", common.LinuxProcessPU)
		collector := &collector.DefaultCollector{}

		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		enforcer := NewWithDefaults(testServerID, collector, nil, secret, constants.LocalServer, "/proc", []string{"0.0.0.0/0"})
		enforcer.packetLogs = true

		Convey("Then enforcer instance must be initialized", func() {
			So(enforcer, ShouldNotBeNil)
		})

		enforcer.Enforce(testServerID, puInfo) // nolint
		defer func() {
			if err := enforcer.Unenforce(testServerID); err != nil {
				fmt.Println("Error", err.Error())
			}
		}()
		PacketFlow := packetgen.NewTemplateFlow()
		_, err = PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeMultipleGoodFlow)
		So(err, ShouldBeNil)
		synPacket, err := PacketFlow.GetFirstSynPacket().ToBytes()
		So(err, ShouldBeNil)
		tcpPacket, err := packet.New(0, synPacket, "0", true)

		Convey("When I run a TCP Syn packet through an invalid existing context (missing IP)", func() {

			_, err1 := enforcer.processApplicationTCPPackets(tcpPacket)
			_, err2 := enforcer.processNetworkTCPPackets(tcpPacket)

			Convey("Then I should see an error for missing IP", func() {

				So(err, ShouldBeNil)
				So(err1, ShouldNotBeNil)
				So(err2, ShouldBeNil)
			})
		})
	})
}

// TestEnforcerConnUnknownState test ensures that enforcer closes the
// connection by converting packets to fin/ack when it finds connection
// to be in unknown state. This happens when enforcer has not seen the
// 3way handshake for a connection.
func TestEnforcerConnUnknownState(t *testing.T) {
	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {
		var puInfo1, puInfo2 *policy.PUInfo
		var enforcer *Datapath
		var err1, err2 error
		Convey("Given I create a two processing unit instances", func() {
			puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, "container", false)
			So(puInfo1, ShouldNotBeNil)
			So(puInfo2, ShouldNotBeNil)
			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)

			Convey("If I send an ack packet from either PU to the other, it is converted into a Fin/Ack", func() {
				PacketFlow := packetgen.NewTemplateFlow()
				_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
				So(err, ShouldBeNil)

				input, err := PacketFlow.GetFirstAckPacket().ToBytes()
				So(err, ShouldBeNil)

				tcpPacket, err := packet.New(0, input, "0", true)
				// create a copy of the ack packet
				tcpPacketCopy := *tcpPacket

				if err == nil && tcpPacket != nil {
					tcpPacket.UpdateIPChecksum()
					tcpPacket.UpdateTCPChecksum()
				}

				_, err1 := enforcer.processApplicationTCPPackets(tcpPacket)

				// Test whether the packet is modified with Fin/Ack
				if tcpPacket.GetTCPFlags() != 0x11 {
					t.Fail()
				}

				_, err2 := enforcer.processNetworkTCPPackets(&tcpPacketCopy)

				if tcpPacket.GetTCPFlags() != 0x11 {
					t.Fail()
				}

				So(err1, ShouldBeNil)
				So(err2, ShouldBeNil)
			})
		})
	})
}

func TestInvalidTokenContext(t *testing.T) {

	Convey("Given I create a new enforcer instance", t, func() {

		secret, err := secrets.NewCompactPKI([]byte(secrets.PrivateKeyPEM), []byte(secrets.PublicPEM), []byte(secrets.CAPEM), secrets.CreateTxtToken(), claimsheader.CompressionTypeNone)
		So(err, ShouldBeNil)
		puInfo := policy.NewPUInfo("SomeProcessingUnitId", common.LinuxProcessPU)

		PacketFlow := packetgen.NewTemplateFlow()
		_, err = PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
		So(err, ShouldBeNil)
		ip := policy.ExtendedMap{
			"brige": testDstIP,
		}
		puInfo.Runtime.SetIPAddresses(ip)
		collector := &collector.DefaultCollector{}

		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		enforcer := NewWithDefaults(testServerID, collector, nil, secret, constants.LocalServer, "/proc", []string{"0.0.0.0/0"})
		enforcer.packetLogs = true
		enforcer.Enforce(testServerID, puInfo) // nolint

		synPacket, err := PacketFlow.GetFirstSynPacket().ToBytes()
		So(err, ShouldBeNil)
		tcpPacket, err := packet.New(0, synPacket, "0", true)

		Convey("When I run a TCP Syn packet through an invalid existing context (missing IP)", func() {

			_, err1 := enforcer.processApplicationTCPPackets(tcpPacket)
			_, err2 := enforcer.processNetworkTCPPackets(tcpPacket)

			Convey("Then I should see an error for missing Token", func() {

				So(err, ShouldBeNil)
				So(err1, ShouldNotBeNil)
				So(err2, ShouldBeNil)
			})
		})
	})
}

func TestPacketHandlingEndToEndPacketsMatch(t *testing.T) {

	SIP := net.IPv4zero
	packetDiffers := false

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {
			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error
			Convey("When I pass multiple packets through the enforcer", func() {

				for k := 0; k < 2; k++ {
					if k == 0 {

						puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, "container", false)
						So(puInfo1, ShouldNotBeNil)
						So(puInfo2, ShouldNotBeNil)
						So(err1, ShouldBeNil)
						So(err2, ShouldBeNil)

					} else if k == 1 {

						puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, "server", false)
						So(puInfo1, ShouldNotBeNil)
						So(puInfo2, ShouldNotBeNil)
						So(err1, ShouldBeNil)
						So(err2, ShouldBeNil)

					}
					PacketFlow := packetgen.NewTemplateFlow()
					_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
					So(err, ShouldBeNil)
					for i := 0; i < PacketFlow.GetNumPackets(); i++ {
						oldPacketFromFlow, err := PacketFlow.GetNthPacket(i).ToBytes()
						So(err, ShouldBeNil)
						oldPacket, err := packet.New(0, oldPacketFromFlow, "0", true)
						if err == nil && oldPacket != nil {
							oldPacket.UpdateIPChecksum()
							oldPacket.UpdateTCPChecksum()
						}

						tcpPacketFromFlow, err := PacketFlow.GetNthPacket(i).ToBytes()
						So(err, ShouldBeNil)
						tcpPacket, err := packet.New(0, tcpPacketFromFlow, "0", true)
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
							SIP = tcpPacket.SourceAddress()
						}
						if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
							!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
							t.Error("Invalid Test Packet")
						}

						_, err = enforcer.processApplicationTCPPackets(tcpPacket)
						So(err, ShouldBeNil)

						if debug {
							fmt.Println("Intermediate packet", i)
							tcpPacket.Print(0)
						}

						output := make([]byte, len(tcpPacket.GetTCPBytes()))
						copy(output, tcpPacket.GetTCPBytes())

						outPacket, errp := packet.New(0, output, "0", true)
						So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
						So(errp, ShouldBeNil)
						_, err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

						if debug {
							fmt.Println("Output packet", i)
							outPacket.Print(0)
						}

						if !reflect.DeepEqual(oldPacket.GetTCPBytes(), outPacket.GetTCPBytes()) {
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

			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error

			Convey("When I pass multiple packets through the enforcer", func() {

				for k := 0; k < 2; k++ {
					if k == 0 {

						puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, "container", false)
						So(puInfo1, ShouldNotBeNil)
						So(puInfo2, ShouldNotBeNil)
						So(err1, ShouldBeNil)
						So(err2, ShouldBeNil)

						firstSynAckProcessed := false

						PacketFlow := packetgen.NewTemplateFlow()
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						for i := 0; i < PacketFlow.GetNumPackets(); i++ {
							oldPacketFromFlow, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, oldPacketFromFlow, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}
							tcpPacketFromFlow, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, tcpPacketFromFlow, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}

							_, err = enforcer.processApplicationTCPPackets(tcpPacket)
							So(err, ShouldBeNil)

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							if tcpPacket.GetTCPFlags()&packet.TCPSynMask != 0 {
								Convey("When I pass a packet with SYN or SYN/ACK flags for packet "+string(i), func() {
									Convey("Then I expect some data payload to exist on the packet "+string(i), func() {
										// In our 3 way security handshake syn and syn-ack packet should grow in length
										So(tcpPacket.IPTotalLen(), ShouldBeGreaterThan, oldPacket.IPTotalLen())
									})
								})
							}

							if !firstSynAckProcessed && tcpPacket.GetTCPFlags()&packet.TCPSynAckMask == packet.TCPAckMask {
								firstSynAckProcessed = true
								Convey("When I pass the first packet with ACK flag for packet "+string(i), func() {
									Convey("Then I expect some data payload to exist on the packet "+string(i), func() {
										// In our 3 way security handshake first ack packet should grow in length
										So(tcpPacket.IPTotalLen(), ShouldBeGreaterThan, oldPacket.IPTotalLen())
									})
								})
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)

							_, err = enforcer.processNetworkTCPPackets(outPacket)
							So(err, ShouldBeNil)

							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}
						}
					} else if k == 1 {

						puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, "server", false)
						So(puInfo1, ShouldNotBeNil)
						So(puInfo2, ShouldNotBeNil)
						So(err1, ShouldBeNil)
						So(err2, ShouldBeNil)

						firstSynAckProcessed := false

						PacketFlow := packetgen.NewTemplateFlow()
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						for i := 0; i < PacketFlow.GetNumPackets(); i++ {
							oldPacketFromFlow, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, oldPacketFromFlow, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}
							tcpPacketFromFlow, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, tcpPacketFromFlow, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}

							_, err = enforcer.processApplicationTCPPackets(tcpPacket)
							So(err, ShouldBeNil)

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							if tcpPacket.GetTCPFlags()&packet.TCPSynMask != 0 {
								Convey("When I pass a packet with SYN or SYN/ACK flags for packet (server) "+string(i), func() {
									Convey("Then I expect some data payload to exist on the packet (server)"+string(i), func() {
										// In our 3 way security handshake syn and syn-ack packet should grow in length
										So(tcpPacket.IPTotalLen(), ShouldBeGreaterThan, oldPacket.IPTotalLen())
									})
								})
							}

							if !firstSynAckProcessed && tcpPacket.GetTCPFlags()&packet.TCPSynAckMask == packet.TCPAckMask {
								firstSynAckProcessed = true
								Convey("When I pass the first packet with ACK flag for packet (server)"+string(i), func() {
									Convey("Then I expect some data payload to exist on the packet (server)"+string(i), func() {
										// In our 3 way security handshake first ack packet should grow in length
										So(tcpPacket.IPTotalLen(), ShouldBeGreaterThan, oldPacket.IPTotalLen())
									})
								})
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)

							_, err = enforcer.processNetworkTCPPackets(outPacket)
							So(err, ShouldBeNil)

							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}
						}
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

			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error

			puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, "server", false)
			So(puInfo1, ShouldNotBeNil)
			So(puInfo2, ShouldNotBeNil)
			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
			Convey("When I pass multiple packets through the enforcer", func() {

				PacketFlow := packetgen.NewTemplateFlow()
				_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
				So(err, ShouldBeNil)
				for i := 0; i < PacketFlow.GetNumPackets(); i++ {
					oldPacketFromFlow, err := PacketFlow.GetNthPacket(i).ToBytes()
					So(err, ShouldBeNil)
					oldPacket, err := packet.New(0, oldPacketFromFlow, "0", true)
					if err == nil && oldPacket != nil {
						oldPacket.UpdateIPChecksum()
						oldPacket.UpdateTCPChecksum()
					}
					tcpPacketFromFlow, err := PacketFlow.GetNthPacket(i).ToBytes()
					So(err, ShouldBeNil)
					tcpPacket, err := packet.New(0, tcpPacketFromFlow, "0", true)
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
						SIP = tcpPacket.SourceAddress()
					}
					if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
						!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
						t.Error("Invalid Test Packet")
					}

					_, err = enforcer.processApplicationTCPPackets(tcpPacket)
					So(err, ShouldBeNil)

					if debug {
						fmt.Println("Intermediate packet", i)
						tcpPacket.Print(0)
					}

					output := make([]byte, len(tcpPacket.GetTCPBytes()))
					copy(output, tcpPacket.GetTCPBytes())

					outPacket, errp := packet.New(0, output, "0", true)
					So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
					So(errp, ShouldBeNil)
					_, err = enforcer.processNetworkTCPPackets(outPacket)
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
		var puInfo1, puInfo2 *policy.PUInfo
		var enforcer *Datapath
		var err1, err2 error
		Convey("Given I create a two processing unit instances", func() {

			for k := 0; k < 2; k++ {
				if k == 0 {

					puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, "container", false)
					So(puInfo1, ShouldNotBeNil)
					So(puInfo2, ShouldNotBeNil)
					So(err1, ShouldBeNil)
					So(err2, ShouldBeNil)
					PacketFlow := packetgen.NewTemplateFlow()
					_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
					So(err, ShouldBeNil)
					/*first packet in TCPFLOW slice is a syn packet*/
					Convey("When i pass a syn packet through the enforcer", func() {

						input, err := PacketFlow.GetFirstSynPacket().ToBytes()
						So(err, ShouldBeNil)

						tcpPacket, err := packet.New(0, input, "0", true)
						if err == nil && tcpPacket != nil {
							tcpPacket.UpdateIPChecksum()
							tcpPacket.UpdateTCPChecksum()
						}

						_, err = enforcer.processApplicationTCPPackets(tcpPacket)
						//After sending syn packet
						CheckAfterAppSynPacket(enforcer, tcpPacket)
						So(err, ShouldBeNil)
						output := make([]byte, len(tcpPacket.GetTCPBytes()))
						copy(output, tcpPacket.GetTCPBytes())

						outPacket, err := packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						_, err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)
						//Check after processing networksyn packet
						CheckAfterNetSynPacket(enforcer, tcpPacket, outPacket)

					})
					Convey("When i pass a SYN and SYN ACK packet through the enforcer", func() {

						input, err := PacketFlow.GetFirstSynPacket().ToBytes()
						So(err, ShouldBeNil)

						tcpPacket, err := packet.New(0, input, "0", true)
						if err == nil && tcpPacket != nil {
							tcpPacket.UpdateIPChecksum()
							tcpPacket.UpdateTCPChecksum()
						}
						_, err = enforcer.processApplicationTCPPackets(tcpPacket)
						So(err, ShouldBeNil)

						output := make([]byte, len(tcpPacket.GetTCPBytes()))
						copy(output, tcpPacket.GetTCPBytes())

						outPacket, err := packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						outPacket.Print(0)
						_, err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

						//Now lets send the synack packet from the server in response
						input, err = PacketFlow.GetFirstSynAckPacket().ToBytes()
						So(err, ShouldBeNil)

						tcpPacket, err = packet.New(0, input, "0", true)
						if err == nil && tcpPacket != nil {
							tcpPacket.UpdateIPChecksum()
							tcpPacket.UpdateTCPChecksum()
						}
						_, err = enforcer.processApplicationTCPPackets(tcpPacket)
						So(err, ShouldBeNil)

						output = make([]byte, len(tcpPacket.GetTCPBytes()))
						copy(output, tcpPacket.GetTCPBytes())

						outPacket, err = packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						outPacketcopy, _ := packet.New(0, output, "0", true)
						_, err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

						CheckAfterNetSynAckPacket(t, enforcer, outPacketcopy, outPacket)

					})

					Convey("When i pass a SYN and SYNACK and another ACK packet through the enforcer", func() {

						input, err := PacketFlow.GetFirstSynPacket().ToBytes()
						So(err, ShouldBeNil)
						tcpPacket, err := packet.New(0, input, "0", true)
						if err == nil && tcpPacket != nil {
							tcpPacket.UpdateIPChecksum()
							tcpPacket.UpdateTCPChecksum()
						}
						_, err = enforcer.processApplicationTCPPackets(tcpPacket)
						So(err, ShouldBeNil)

						output := make([]byte, len(tcpPacket.GetTCPBytes()))
						copy(output, tcpPacket.GetTCPBytes())

						outPacket, err := packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						_, err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

						//Now lets send the synack packet from the server in response
						input, err = PacketFlow.GetFirstSynAckPacket().ToBytes()
						So(err, ShouldBeNil)

						tcpPacket, err = packet.New(0, input, "0", true)
						if err == nil && tcpPacket != nil {
							tcpPacket.UpdateIPChecksum()
							tcpPacket.UpdateTCPChecksum()
						}
						_, err = enforcer.processApplicationTCPPackets(tcpPacket)
						So(err, ShouldBeNil)

						output = make([]byte, len(tcpPacket.GetTCPBytes()))
						copy(output, tcpPacket.GetTCPBytes())

						outPacket, err = packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						_, err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

						input, err = PacketFlow.GetFirstAckPacket().ToBytes()
						So(err, ShouldBeNil)

						tcpPacket, err = packet.New(0, input, "0", true)
						if err == nil && tcpPacket != nil {
							tcpPacket.UpdateIPChecksum()
							tcpPacket.UpdateTCPChecksum()
						}
						_, err = enforcer.processApplicationTCPPackets(tcpPacket)
						CheckAfterAppAckPacket(enforcer, tcpPacket)
						So(err, ShouldBeNil)

						output = make([]byte, len(tcpPacket.GetTCPBytes()))
						copy(output, tcpPacket.GetTCPBytes())

						outPacket, err = packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						CheckBeforeNetAckPacket(enforcer, tcpPacket, outPacket, false)
						_, err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

					})

				} else if k == 1 {

					puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, "server", false)
					So(puInfo1, ShouldNotBeNil)
					So(puInfo2, ShouldNotBeNil)
					So(err1, ShouldBeNil)
					So(err2, ShouldBeNil)
					PacketFlow := packetgen.NewTemplateFlow()
					_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
					So(err, ShouldBeNil)
					/*first packet in TCPFLOW slice is a syn packet*/
					Convey("When i pass a syn packet through the enforcer (server)", func() {

						input, err := PacketFlow.GetFirstSynPacket().ToBytes()
						So(err, ShouldBeNil)

						tcpPacket, err := packet.New(0, input, "0", true)
						if err == nil && tcpPacket != nil {
							tcpPacket.UpdateIPChecksum()
							tcpPacket.UpdateTCPChecksum()
						}

						_, err = enforcer.processApplicationTCPPackets(tcpPacket)
						//After sending syn packet
						CheckAfterAppSynPacket(enforcer, tcpPacket)
						So(err, ShouldBeNil)
						output := make([]byte, len(tcpPacket.GetTCPBytes()))
						copy(output, tcpPacket.GetTCPBytes())

						outPacket, err := packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						_, err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)
						//Check after processing networksyn packet
						CheckAfterNetSynPacket(enforcer, tcpPacket, outPacket)

					})
					Convey("When i pass a SYN and SYN ACK packet through the enforcer (server)", func() {

						input, err := PacketFlow.GetFirstSynPacket().ToBytes()
						So(err, ShouldBeNil)

						tcpPacket, err := packet.New(0, input, "0", true)
						if err == nil && tcpPacket != nil {
							tcpPacket.UpdateIPChecksum()
							tcpPacket.UpdateTCPChecksum()
						}
						_, err = enforcer.processApplicationTCPPackets(tcpPacket)
						So(err, ShouldBeNil)

						output := make([]byte, len(tcpPacket.GetTCPBytes()))
						copy(output, tcpPacket.GetTCPBytes())

						outPacket, err := packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						outPacket.Print(0)
						_, err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

						//Now lets send the synack packet from the server in response
						input, err = PacketFlow.GetFirstSynAckPacket().ToBytes()
						So(err, ShouldBeNil)

						tcpPacket, err = packet.New(0, input, "0", true)
						if err == nil && tcpPacket != nil {
							tcpPacket.UpdateIPChecksum()
							tcpPacket.UpdateTCPChecksum()
						}
						_, err = enforcer.processApplicationTCPPackets(tcpPacket)
						So(err, ShouldBeNil)

						output = make([]byte, len(tcpPacket.GetTCPBytes()))
						copy(output, tcpPacket.GetTCPBytes())

						outPacket, err = packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						outPacketcopy, _ := packet.New(0, output, "0", true)
						_, err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

						CheckAfterNetSynAckPacket(t, enforcer, outPacketcopy, outPacket)

					})

					Convey("When i pass a SYN and SYNACK and another ACK packet through the enforcer (server)", func() {

						input, err := PacketFlow.GetFirstSynPacket().ToBytes()
						So(err, ShouldBeNil)

						tcpPacket, err := packet.New(0, input, "0", true)
						if err == nil && tcpPacket != nil {
							tcpPacket.UpdateIPChecksum()
							tcpPacket.UpdateTCPChecksum()
						}
						_, err = enforcer.processApplicationTCPPackets(tcpPacket)
						So(err, ShouldBeNil)

						output := make([]byte, len(tcpPacket.GetTCPBytes()))
						copy(output, tcpPacket.GetTCPBytes())

						outPacket, err := packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						_, err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

						//Now lets send the synack packet from the server in response
						input, err = PacketFlow.GetFirstSynAckPacket().ToBytes()
						So(err, ShouldBeNil)

						tcpPacket, err = packet.New(0, input, "0", true)
						if err == nil && tcpPacket != nil {
							tcpPacket.UpdateIPChecksum()
							tcpPacket.UpdateTCPChecksum()
						}
						_, err = enforcer.processApplicationTCPPackets(tcpPacket)
						So(err, ShouldBeNil)

						output = make([]byte, len(tcpPacket.GetTCPBytes()))
						copy(output, tcpPacket.GetTCPBytes())

						outPacket, err = packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						_, err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

						input, err = PacketFlow.GetFirstAckPacket().ToBytes()
						So(err, ShouldBeNil)

						tcpPacket, err = packet.New(0, input, "0", true)
						if err == nil && tcpPacket != nil {
							tcpPacket.UpdateIPChecksum()
							tcpPacket.UpdateTCPChecksum()
						}
						_, err = enforcer.processApplicationTCPPackets(tcpPacket)
						CheckAfterAppAckPacket(enforcer, tcpPacket)
						So(err, ShouldBeNil)

						output = make([]byte, len(tcpPacket.GetTCPBytes()))
						copy(output, tcpPacket.GetTCPBytes())

						outPacket, err = packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						CheckBeforeNetAckPacket(enforcer, tcpPacket, outPacket, false)
						_, err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

					})
				}
			}
		})
	})
}

func CheckAfterAppSynPacket(enforcer *Datapath, tcpPacket *packet.Packet) {

	appConn, err := enforcer.appOrigConnectionTracker.Get(tcpPacket.L4FlowHash())
	So(appConn.(*connection.TCPConnection).GetState(), ShouldEqual, connection.TCPSynSend)
	So(err, ShouldBeNil)

}

func CheckAfterNetSynPacket(enforcer *Datapath, tcpPacket, outPacket *packet.Packet) {

	appConn, err := enforcer.netOrigConnectionTracker.Get(tcpPacket.L4FlowHash())
	So(err, ShouldBeNil)
	So(appConn.(*connection.TCPConnection).GetState(), ShouldEqual, connection.TCPSynReceived)
}

func CheckAfterNetSynAckPacket(t *testing.T, enforcer *Datapath, tcpPacket, outPacket *packet.Packet) {

	netconn, err := enforcer.sourcePortConnectionCache.Get(outPacket.SourcePortHash(packet.PacketTypeNetwork))
	So(err, ShouldBeNil)
	So(netconn.(*connection.TCPConnection).GetState(), ShouldEqual, connection.TCPSynAckReceived)
}

func CheckAfterAppAckPacket(enforcer *Datapath, tcpPacket *packet.Packet) {

	appConn, err := enforcer.appOrigConnectionTracker.Get(tcpPacket.L4FlowHash())
	So(err, ShouldBeNil)
	So(appConn.(*connection.TCPConnection).GetState(), ShouldEqual, connection.TCPAckSend)
}

func CheckBeforeNetAckPacket(enforcer *Datapath, tcpPacket, outPacket *packet.Packet, isReplay bool) {

	appConn, err := enforcer.netOrigConnectionTracker.Get(tcpPacket.L4FlowHash())
	So(err, ShouldBeNil)
	if !isReplay {
		So(appConn.(*connection.TCPConnection).GetState(), ShouldEqual, connection.TCPSynAckSend)
	} else {
		So(appConn.(*connection.TCPConnection).GetState(), ShouldBeGreaterThan, connection.TCPSynAckSend)
	}
}

func TestPacketHandlingSrcPortCacheBehavior(t *testing.T) {

	SIP := net.IPv4zero

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {

			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error

			puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, "server", false)
			So(puInfo1, ShouldNotBeNil)
			So(puInfo2, ShouldNotBeNil)
			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
			Convey("When I pass multiple packets through the enforcer", func() {

				PacketFlow := packetgen.NewTemplateFlow()
				_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
				So(err, ShouldBeNil)
				for i := 0; i < PacketFlow.GetNumPackets(); i++ {

					start, err := PacketFlow.GetNthPacket(i).ToBytes()
					So(err, ShouldBeNil)
					input, err := PacketFlow.GetNthPacket(i).ToBytes()
					So(err, ShouldBeNil)

					oldPacket, err := packet.New(0, start, "0", true)
					if err == nil && oldPacket != nil {
						oldPacket.UpdateIPChecksum()
						oldPacket.UpdateTCPChecksum()
					}
					tcpPacket, err := packet.New(0, input, "0", true)
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
						SIP = tcpPacket.SourceAddress()
					}
					if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
						!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
						t.Error("Invalid Test Packet")
					}

					_, err = enforcer.processApplicationTCPPackets(tcpPacket)
					So(err, ShouldBeNil)

					if debug {
						fmt.Println("Intermediate packet", i)
						tcpPacket.Print(0)
					}

					if reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
						// SYN Packets only
						if tcpPacket.GetTCPFlags()&packet.TCPSynAckMask == packet.TCPSynMask {
							Convey("When I pass an application packet with SYN flag for packet "+string(i), func() {
								Convey("Then I expect src port cache to be populated "+string(i), func() {
									fmt.Println("SrcPortHash:" + tcpPacket.SourcePortHash(packet.PacketTypeApplication))
									cs, es := enforcer.sourcePortConnectionCache.Get(tcpPacket.SourcePortHash(packet.PacketTypeApplication))
									So(cs, ShouldNotBeNil)
									So(es, ShouldBeNil)
								})
							})
						}
					}

					output := make([]byte, len(tcpPacket.GetTCPBytes()))
					copy(output, tcpPacket.GetTCPBytes())

					outPacket, errp := packet.New(0, output, "0", true)
					So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
					So(errp, ShouldBeNil)
					_, err = enforcer.processNetworkTCPPackets(outPacket)
					So(err, ShouldBeNil)

					if debug {
						fmt.Println("Output packet", i)
						outPacket.Print(0)
					}

					if reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) {
						if outPacket.GetTCPFlags()&packet.TCPSynAckMask == packet.TCPSynAckMask {
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
	Convey("Given I create a new enforcer instance", t, func() {
		secret, err := secrets.NewCompactPKI([]byte(secrets.PrivateKeyPEM), []byte(secrets.PublicPEM), []byte(secrets.CAPEM), secrets.CreateTxtToken(), claimsheader.CompressionTypeNone)
		So(err, ShouldBeNil)
		collector := &collector.DefaultCollector{}
		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}
		enforcer := NewWithDefaults(testServerID, collector, nil, secret, constants.LocalServer, "/proc", []string{"0.0.0.0/0"})
		enforcer.packetLogs = true
		contextID := "123"

		puInfo := policy.NewPUInfo(contextID, common.ContainerPU)

		// Should fail: Not in cache
		err = enforcer.Unenforce(contextID)
		if err == nil {
			t.Errorf("Expected failure, no contextID in cache")
		}

		ip := policy.ExtendedMap{"bridge": "127.0.0.1"}
		puInfo.Runtime.SetIPAddresses(ip)
		ipl := policy.ExtendedMap{"bridge": "127.0.0.1"}
		puInfo.Policy.SetIPAddresses(ipl)

		ip = policy.ExtendedMap{"bridge": "127.0.0.1"}
		puInfo.Runtime.SetIPAddresses(ip)

		ipl = policy.ExtendedMap{"bridge": "127.0.0.1"}
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
	})
}

func TestDoCreatePU(t *testing.T) {

	Convey("Given an initialized enforcer for Linux Processes", t, func() {
		secret, err := secrets.NewCompactPKI([]byte(secrets.PrivateKeyPEM), []byte(secrets.PublicPEM), []byte(secrets.CAPEM), secrets.CreateTxtToken(), claimsheader.CompressionTypeNone)
		So(err, ShouldBeNil)
		collector := &collector.DefaultCollector{}

		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		enforcer := NewWithDefaults(testServerID, collector, nil, secret, constants.LocalServer, "/proc", []string{"0.0.0.0/0"})
		enforcer.packetLogs = true
		enforcer.mode = constants.LocalServer
		contextID := "124"
		puInfo := policy.NewPUInfo(contextID, common.LinuxProcessPU)

		spec, _ := portspec.NewPortSpecFromString("80", nil)
		puInfo.Runtime.SetOptions(policy.OptionsType{
			CgroupMark: "100",
			Services: []common.Service{
				{
					Protocol: uint8(6),
					Ports:    spec,
				},
			},
		})

		Convey("When I create a new PU", func() {
			err := enforcer.Enforce(contextID, puInfo)

			Convey("It should succeed", func() {
				So(err, ShouldBeNil)
				_, err := enforcer.puFromContextID.Get(contextID)
				So(err, ShouldBeNil)
				_, err1 := enforcer.puFromMark.Get("100")
				So(err1, ShouldBeNil)
				_, err2 := enforcer.contextIDFromTCPPort.GetSpecValueFromPort(80)
				So(err2, ShouldBeNil)
				So(enforcer.puFromIP, ShouldBeNil)
			})
		})
	})

	Convey("Given an initialized enforcer for Linux Processes", t, func() {
		secret, err := secrets.NewCompactPKI([]byte(secrets.PrivateKeyPEM), []byte(secrets.PublicPEM), []byte(secrets.CAPEM), secrets.CreateTxtToken(), claimsheader.CompressionTypeNone)
		So(err, ShouldBeNil)
		collector := &collector.DefaultCollector{}
		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		enforcer := NewWithDefaults(testServerID, collector, nil, secret, constants.LocalServer, "/proc", []string{"0.0.0.0/0"})
		enforcer.packetLogs = true
		enforcer.mode = constants.LocalServer
		contextID := "125"
		puInfo := policy.NewPUInfo(contextID, common.LinuxProcessPU)

		Convey("When I create a new PU without ports or mark", func() {
			err := enforcer.Enforce(contextID, puInfo)

			Convey("It should succeed", func() {
				So(err, ShouldBeNil)
				_, err := enforcer.puFromContextID.Get(contextID)
				So(err, ShouldBeNil)
				So(enforcer.puFromIP, ShouldBeNil)
			})
		})
	})

	Convey("Given an initialized enforcer for remote Linux Containers", t, func() {
		secret, err := secrets.NewCompactPKI([]byte(secrets.PrivateKeyPEM), []byte(secrets.PublicPEM), []byte(secrets.CAPEM), secrets.CreateTxtToken(), claimsheader.CompressionTypeNone)
		So(err, ShouldBeNil)
		collector := &collector.DefaultCollector{}

		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		enforcer := NewWithDefaults(testServerID, collector, nil, secret, constants.LocalServer, "/proc", []string{"0.0.0.0/0"})
		enforcer.packetLogs = true
		enforcer.mode = constants.RemoteContainer

		contextID := "126"
		puInfo := policy.NewPUInfo(contextID, common.ContainerPU)

		Convey("When I create a new PU without an IP", func() {
			err := enforcer.Enforce(contextID, puInfo)

			Convey("It should succeed ", func() {
				So(err, ShouldBeNil)
				So(enforcer.puFromIP, ShouldNotBeNil)
			})
		})
	})
}

func TestContextFromIP(t *testing.T) {

	Convey("Given an initialized enforcer for Linux Processes", t, func() {
		secret, err := secrets.NewCompactPKI([]byte(secrets.PrivateKeyPEM), []byte(secrets.PublicPEM), []byte(secrets.CAPEM), secrets.CreateTxtToken(), claimsheader.CompressionTypeNone)
		So(err, ShouldBeNil)
		collector := &collector.DefaultCollector{}

		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		enforcer := NewWithDefaults(testServerID, collector, nil, secret, constants.RemoteContainer, "/proc", []string{"0.0.0.0/0"})
		enforcer.packetLogs = true

		puInfo := policy.NewPUInfo("SomePU", common.ContainerPU)

		context, err := pucontext.NewPU("SomePU", puInfo, 10*time.Second)
		contextID := "AporetoContext"
		So(err, ShouldBeNil)

		Convey("If I try to get context based on IP and its  not there and its a local container it should fail ", func() {
			_, err := enforcer.contextFromIP(true, "", 0, packet.IPProtocolTCP)
			So(err, ShouldNotBeNil)
		})

		Convey("If there is no IP match, it should try the mark for app packets ", func() {
			enforcer.puFromMark.AddOrUpdate("100", context)
			enforcer.mode = constants.LocalServer

			Convey("If the mark exists", func() {
				ctx, err := enforcer.contextFromIP(true, "100", 0, packet.IPProtocolTCP)
				So(err, ShouldBeNil)
				So(ctx, ShouldNotBeNil)
				So(ctx, ShouldEqual, context)
			})

			Convey("If the mark doesn't exist", func() {
				_, err := enforcer.contextFromIP(true, "2000", 0, packet.IPProtocolTCP)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If there is no IP match, it should try the port for net packets ", func() {
			s, _ := portspec.NewPortSpec(8000, 8000, contextID)
			enforcer.contextIDFromTCPPort.AddPortSpec(s)
			enforcer.puFromContextID.AddOrUpdate(contextID, context)
			enforcer.mode = constants.LocalServer

			Convey("If the port exists", func() {
				ctx, err := enforcer.contextFromIP(false, "", 8000, packet.IPProtocolTCP)
				So(err, ShouldBeNil)
				So(ctx, ShouldNotBeNil)
				So(ctx, ShouldEqual, context)
			})

			Convey("If the port doesn't exist", func() {
				_, err := enforcer.contextFromIP(false, "", 9000, packet.IPProtocolTCP)
				So(err, ShouldNotBeNil)
			})
		})

	})
}

func TestInvalidPacket(t *testing.T) {

	var puInfo1, puInfo2 *policy.PUInfo
	var enforcer *Datapath
	var err1, err2 error

	Convey("When I receive an invalid packet", t, func() {

		for k := 0; k < 2; k++ {
			if k == 0 {

				puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, "container", false)
				So(puInfo1, ShouldNotBeNil)
				So(puInfo2, ShouldNotBeNil)
				So(err1, ShouldBeNil)
				So(err2, ShouldBeNil)

			} else if k == 1 {

				puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, "server", false)
				So(puInfo1, ShouldNotBeNil)
				So(puInfo2, ShouldNotBeNil)
				So(err1, ShouldBeNil)
				So(err2, ShouldBeNil)

			}

			InvalidTCPFlow := [][]byte{
				{ /*0x4a, 0x1d, 0x70, 0xcf, 0xa6, 0xe5, 0xb8, 0xe8, 0x56, 0x32, 0x0b, 0xde, 0x08, 0x00,*/ 0x45, 0x00, 0x00, 0x40, 0xf4, 0x1f, 0x44, 0x00, 0x40, 0x06, 0xa9, 0x6f, 0x0a, 0x01, 0x0a, 0x4c, 0xa4, 0x43, 0xe4, 0x98, 0xe1, 0xa1, 0x00, 0x50, 0x4d, 0xa6, 0xac, 0x48, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff, 0x6b, 0x6c, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x05, 0x01, 0x01, 0x08, 0x0a, 0x1b, 0x4f, 0x37, 0x38, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x4a, 0x1d, 0x70, 0xcf},
			}

			for _, p := range InvalidTCPFlow {
				tcpPacket, err := packet.New(0, p, "0", true)
				So(err, ShouldBeNil)
				_, err = enforcer.processApplicationTCPPackets(tcpPacket)
				So(err, ShouldBeNil)
				output := make([]byte, len(tcpPacket.GetTCPBytes()))
				copy(output, tcpPacket.GetTCPBytes())
				outpacket, err := packet.New(0, output, "0", true)
				So(err, ShouldBeNil)
				//Detach the data and parse token should fail
				err = outpacket.TCPDataDetach(binary.BigEndian.Uint16([]byte{0x0, p[32]})/4 - 20)
				So(err, ShouldBeNil)
				_, err = enforcer.processNetworkTCPPackets(outpacket)
				So(err, ShouldNotBeNil)
			}
		}
	})
}

func TestFlowReportingGoodFlow(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	SIP := net.IPv4zero
	packetDiffers := false

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {

			puInfo1, puInfo2, enforcer, err1, err2, _, _ := setupProcessingUnitsInDatapathAndEnforce(nil, "container", false)

			So(puInfo1, ShouldNotBeNil)
			So(puInfo2, ShouldNotBeNil)
			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)

			Convey("When I pass multiple packets (3-way handshake) through the enforcer", func() {

				Convey("Then I expect the flow to be reported only once", func() {
					for k := 0; k < 2; k++ {
						if k == 0 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						}
						PacketFlow := packetgen.NewPacketFlow("aa:ff:aa:ff:aa:ff", "ff:aa:ff:aa:ff:aa", testSrcIP, testDstIP, 666, 80)
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						for i := 0; i < PacketFlow.GetNumPackets(); i++ {
							start, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, start, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}
							input, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, input, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}

							_, err = enforcer.processApplicationTCPPackets(tcpPacket)
							So(err, ShouldBeNil)

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)
							_, err = enforcer.processNetworkTCPPackets(outPacket)

							So(err, ShouldBeNil)

							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}

							if !reflect.DeepEqual(oldPacket.GetTCPBytes(), outPacket.GetTCPBytes()) {
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
					}
					Convey("Then I expect all the input and output packets (after encoding and decoding) to be same", func() {

						So(packetDiffers, ShouldEqual, false)
					})
				})
			})
		})
	})
}

func TestFlowReportingGoodFlowWithReject(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	SIP := net.IPv4zero
	packetDiffers := false

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {

			puInfo1, puInfo2, enforcer, err1, err2, _, _ := setupProcessingUnitsInDatapathAndEnforce(nil, "container", false)

			So(puInfo1, ShouldNotBeNil)
			So(puInfo2, ShouldNotBeNil)
			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)

			Convey("When I pass multiple packets (3-way handshake) through the enforcer", func() {

				Convey("Then I expect the flow to be reported only once", func() {
					for k := 0; k < 2; k++ {
						if k == 0 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						}
						PacketFlow := packetgen.NewPacketFlow("aa:ff:aa:ff:aa:ff", "ff:aa:ff:aa:ff:aa", testSrcIP, testDstIP, 666, 80)
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						for i := 0; i < PacketFlow.GetNumPackets(); i++ {
							start, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, start, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}
							input, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, input, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}
							enforcer.mutualAuthorization = true
							enforcer.processApplicationTCPPackets(tcpPacket) // nolint

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)
							enforcer.processNetworkTCPPackets(outPacket) // nolint

							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}
						}
					}
					Convey("Then I expect all the input and output packets (after encoding and decoding) to be same", func() {

						So(packetDiffers, ShouldEqual, false)
					})
				})
			})
		})
	})
}

func TestFlowReportingSynPacketOnlyInFlow(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	SIP := net.IPv4zero
	packetDiffers := false

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {
			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error

			Convey("When I pass SYN packet through the enforcer", func() {

				Convey("Then I expect the flow not to be reported", func() {
					for k := 0; k < 2; k++ {
						if k == 0 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(0)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(0)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						}
						PacketFlow := packetgen.NewTemplateFlow()
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						for i := 0; i < PacketFlow.GetSynPackets().GetNumPackets(); i++ {
							start, err := PacketFlow.GetSynPackets().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, start, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}
							input, err := PacketFlow.GetSynPackets().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, input, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}

							_, err = enforcer.processApplicationTCPPackets(tcpPacket)
							CheckAfterAppSynPacket(enforcer, tcpPacket)
							So(err, ShouldBeNil)

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)
							_, err = enforcer.processNetworkTCPPackets(outPacket)
							CheckAfterNetSynPacket(enforcer, tcpPacket, outPacket)
							So(err, ShouldBeNil)

							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}

							if !reflect.DeepEqual(oldPacket.GetTCPBytes(), outPacket.GetTCPBytes()) {
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
					}
					Convey("Then I expect all the input and output packets (after encoding and decoding) to be same", func() {

						So(packetDiffers, ShouldEqual, false)
					})
				})
			})
		})
	})
}

func TestFlowReportingUptoSynAckPacketInFlow(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	SIP := net.IPv4zero
	packetDiffers := false

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {
			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error

			Convey("When I pass upto SYNACK packet through the enforcer", func() {

				Convey("Then I expect the flow not to be reported", func() {
					for k := 0; k < 2; k++ {
						if k == 0 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(0)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(0)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						}
						PacketFlow := packetgen.NewTemplateFlow()
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						for i := 0; i < PacketFlow.GetUptoFirstSynAckPacket().GetNumPackets(); i++ {

							start, err := PacketFlow.GetUptoFirstSynAckPacket().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, start, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}
							input, err := PacketFlow.GetUptoFirstSynAckPacket().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, input, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}

							_, err = enforcer.processApplicationTCPPackets(tcpPacket)
							So(err, ShouldBeNil)

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)

							outPacketcopy, _ := packet.New(0, output, "0", true)
							_, err = enforcer.processNetworkTCPPackets(outPacket)
							So(err, ShouldBeNil)

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								CheckAfterNetSynAckPacket(t, enforcer, outPacketcopy, outPacket)
							}

							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}

							if !reflect.DeepEqual(oldPacket.GetTCPBytes(), outPacket.GetTCPBytes()) {
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
					}
					Convey("Then I expect all the input and output packets (after encoding and decoding) to be same", func() {

						So(packetDiffers, ShouldEqual, false)
					})
				})
			})
		})
	})
}

func TestFlowReportingUptoFirstAckPacketInFlow(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	SIP := net.IPv4zero
	packetDiffers := false

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {
			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error

			Convey("When I pass upto ACK packet through the enforcer", func() {

				Convey("Then I expect the flow to be reported as accepted only once", func() {
					for k := 0; k < 2; k++ {
						if k == 0 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						}
						PacketFlow := packetgen.NewTemplateFlow()
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						for i := 0; i < PacketFlow.GetUptoFirstAckPacket().GetNumPackets(); i++ {

							start, err := PacketFlow.GetUptoFirstAckPacket().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, start, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}

							input, err := PacketFlow.GetUptoFirstAckPacket().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, input, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}

							_, err = enforcer.processApplicationTCPPackets(tcpPacket)
							So(err, ShouldBeNil)
							if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								CheckAfterAppAckPacket(enforcer, tcpPacket)
							}

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)
							if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								CheckBeforeNetAckPacket(enforcer, tcpPacket, outPacket, false)
							}
							_, err = enforcer.processNetworkTCPPackets(outPacket)
							So(err, ShouldBeNil)

							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}

							if !reflect.DeepEqual(oldPacket.GetTCPBytes(), outPacket.GetTCPBytes()) {
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
					}
					Convey("Then I expect all the input and output packets (after encoding and decoding) to be same", func() {

						So(packetDiffers, ShouldEqual, false)
					})
				})
			})
		})
	})
}

func TestFlowReportingManyPacketsInFlow(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	SIP := net.IPv4zero
	packetDiffers := false

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {
			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error

			Convey("When I pass multiple packets through the enforcer", func() {

				Convey("Then I expect the flow to be reported only once", func() {
					for k := 0; k < 2; k++ {
						if k == 0 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						}
						PacketFlow := packetgen.NewTemplateFlow()
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						for i := 0; i < PacketFlow.GetNumPackets(); i++ {

							start, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, start, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}
							input, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, input, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}

							_, err = enforcer.processApplicationTCPPackets(tcpPacket)
							So(err, ShouldBeNil)

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)
							_, err = enforcer.processNetworkTCPPackets(outPacket)

							So(err, ShouldBeNil)

							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}

							if !reflect.DeepEqual(oldPacket.GetTCPBytes(), outPacket.GetTCPBytes()) {
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
					}
					Convey("Then I expect all the input and output packets (after encoding and decoding) to be same", func() {

						So(packetDiffers, ShouldEqual, false)
					})
				})
			})
		})
	})
}

func TestFlowReportingReplayAttack(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	SIP := net.IPv4zero

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {
			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error

			Convey("When I pass multiple packets with replay attacks through the enforcer", func() {

				Convey("Then I expect the flow to be reported only once with states intact", func() {
					for k := 0; k < 2; k++ {
						if k == 0 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						}
						PacketFlow := packetgen.NewTemplateFlow()
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						var isAckPacket, isChecked, isSynPacket, isSynAckPacket, isSynAckNetPacket bool
						var countSynAckPacket int
						var checkAfterAppAckFlag, checkBeforeNetAckFlag bool
						var connSynAck [][]byte

						for i := 0; i < PacketFlow.GetNumPackets(); i++ {

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && countSynAckPacket <= 1 {
								i = i - 1
								countSynAckPacket++
							}

							if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && !isAckPacket {
								i = i - 1
								isAckPacket = true
							}
							start, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, start, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}
							input, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, input, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() && isSynPacket {
								fmt.Println("This a app (A)", i)
								_, err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							} else if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && isSynAckPacket {
								fmt.Println("This a app (B)", i)
								_, err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							} else if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								fmt.Println("This a app (C)", i)
								_, err = enforcer.processApplicationTCPPackets(tcpPacket)
								isSynAckPacket = true
								So(err, ShouldBeNil)
							} else {
								fmt.Println("This a app (D)", i)
								_, err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() {
								CheckAfterAppSynPacket(enforcer, tcpPacket)
							}

							if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && !checkAfterAppAckFlag {
								CheckAfterAppAckPacket(enforcer, tcpPacket)
								checkAfterAppAckFlag = true

							}

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {

								netconn, _ := enforcer.sourcePortConnectionCache.Get(outPacket.SourcePortHash(packet.PacketTypeNetwork))
								connSynAck = append(connSynAck, netconn.(*connection.TCPConnection).Auth.LocalContext)

							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								if isChecked {
									netconn, _ := enforcer.sourcePortConnectionCache.Get(outPacket.SourcePortHash(packet.PacketTypeNetwork))
									So(netconn, ShouldNotBeNil)
								}
								isChecked = true
							}
							if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && !PacketFlow.GetNthPacket(i).GetTCPFin() && !checkBeforeNetAckFlag {
								CheckBeforeNetAckPacket(enforcer, tcpPacket, outPacket, checkBeforeNetAckFlag)
								checkBeforeNetAckFlag = true
							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() && isSynPacket {
								fmt.Println("This is net (A)", i)
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							} else if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && isSynAckNetPacket {
								fmt.Println("This a net (B)", i)
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							} else if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								fmt.Println("This a net (C)", i)
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								isSynAckNetPacket = true
								So(err, ShouldBeNil)
							} else {
								fmt.Println("This is net (C)", i)
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								isSynPacket = true
								So(err, ShouldBeNil)
							}
							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}

						}
						for j := 0; j < len(connSynAck)-1; j++ {
							for k := 0; k < len(connSynAck[j]); k++ {
								So(connSynAck[j][k], ShouldEqual, connSynAck[j+1][k])
							}
						}
					}
				})
			})
		})
	})
}

func TestFlowReportingPacketDelays(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	SIP := net.IPv4zero

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {

			puInfo1, puInfo2, enforcer, err1, err2, _, _ := setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)

			So(puInfo1, ShouldNotBeNil)
			So(puInfo2, ShouldNotBeNil)
			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)

			Convey("When I pass multiple packets with delay of Syn and SynAck packets", func() {

				Convey("Then I expect the flow to be reported only once with states intact", func() {
					for k := 0; k < 2; k++ {
						if k == 0 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						}
						PacketFlow := packetgen.NewTemplateFlow()
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						var isAckPacket, isSynReceived, isSynAckReceived bool

						for i := 0; i < PacketFlow.GetNumPackets(); i++ {

							if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && !isAckPacket {
								i = 0
								isAckPacket = true
							}

							input, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, input, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}
							start, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, start, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() && isSynReceived {
								fmt.Println("This is App (A)", i)
								isSynAckReceived = true
								_, err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							} else if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && isSynAckReceived {
								fmt.Println("This is App (B)", i)
								isSynAckReceived = true
								_, err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							} else {
								fmt.Println("This is App (C)", i)
								_, err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							}
							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() && isSynAckReceived {
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							} else if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && isSynAckReceived {
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							} else {
								fmt.Println("This is net (c)", i)
								isSynReceived = true
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							}
							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}
						}
					}
				})
			})
		})
	})
}

func TestForCacheCheckAfter60Seconds(t *testing.T) {

	SIP := net.IPv4zero

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {
			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error

			Convey("When I pass multiple packets through the enforcer", func() {

				Convey("Then I expect the cache to be empty after 60 seconds", func() {
					for k := 0; k < 2; k++ {
						if k == 0 {

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						}
						PacketFlow := packetgen.NewTemplateFlow()
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						var isAckPacket, isChecked bool
						var countSynAckPacket int
						var connSynAck [][]byte

						for i := 0; i < PacketFlow.GetNumPackets(); i++ {

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && countSynAckPacket <= 1 {
								i = i - 1
								countSynAckPacket++
							}

							if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && !isAckPacket {
								i = i - 1
								isAckPacket = true
							}

							start, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, start, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}
							input, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, input, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}

							enforcer.processApplicationTCPPackets(tcpPacket) // nolint: errcheck

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {

								netconn, _ := enforcer.sourcePortConnectionCache.Get(outPacket.SourcePortHash(packet.PacketTypeNetwork))
								connSynAck = append(connSynAck, netconn.(*connection.TCPConnection).Auth.LocalContext)

							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								if isChecked {
									time.Sleep(time.Second * 61)
									netconn, err := enforcer.sourcePortConnectionCache.Get(outPacket.SourcePortHash(packet.PacketTypeNetwork))
									So(netconn, ShouldBeNil)
									So(err, ShouldNotBeNil)
								}
								isChecked = true
							}

							enforcer.processNetworkTCPPackets(outPacket) // nolint: errcheck

							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}

						}
						for j := 0; j < len(connSynAck)-1; j++ {
							for k := 0; k < len(connSynAck[j]); k++ {
								So(connSynAck[j][k], ShouldEqual, connSynAck[j+1][k])
							}
						}
					}
				})
			})
		})
	})
}
func TestFlowReportingInvalidSyn(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	SIP := net.IPv4zero
	packetDiffers := false

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {
			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error

			Convey("When I pass SYN packet without a token through the enforcer", func() {

				Convey("Then I expect the rejected flow to be reported once", func() {
					for k := 0; k < 2; k++ {
						if k == 0 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						}
						PacketFlow := packetgen.NewTemplateFlow()
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						for i := 0; i < PacketFlow.GetSynPackets().GetNumPackets(); i++ {

							start, err := PacketFlow.GetSynPackets().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, start, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}

							input, err := PacketFlow.GetSynPackets().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, input, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)
							_, err = enforcer.processNetworkTCPPackets(outPacket)
							So(err, ShouldNotBeNil)

							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}

							if !reflect.DeepEqual(oldPacket.GetTCPBytes(), outPacket.GetTCPBytes()) {
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
					}
					Convey("Then I expect all the input and output packets (after encoding and decoding) to be same", func() {

						So(packetDiffers, ShouldEqual, false)
					})
				})
			})
		})
	})
}

func TestFlowReportingUptoInvalidSynAck(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	SIP := net.IPv4zero
	packetDiffers := false

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {
			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error

			Convey("When I pass upto SynAck packet with no token for SynAck through the enforcer", func() {

				Convey("Then I expect the rejected flow to be reported", func() {
					for k := 0; k < 2; k++ {
						if k == 0 {

							mockCollector.EXPECT().CollectFlowEvent(gomock.Any()).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							mockCollector.EXPECT().CollectFlowEvent(gomock.Any()).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						}
						PacketFlow := packetgen.NewTemplateFlow()
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						for i := 0; i < PacketFlow.GetUptoFirstSynAckPacket().GetNumPackets(); i++ {
							start, err := PacketFlow.GetUptoFirstSynAckPacket().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)

							oldPacket, err := packet.New(0, start, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}
							input, err := PacketFlow.GetUptoFirstSynAckPacket().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, input, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() {
								_, err = enforcer.processApplicationTCPPackets(tcpPacket)

								So(err, ShouldBeNil)
							}

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() {
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldNotBeNil)
							}

							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}

							if !reflect.DeepEqual(oldPacket.GetTCPBytes(), outPacket.GetTCPBytes()) {
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
					}
					Convey("Then I expect all the input and output packets (after encoding and decoding) to be same", func() {

						So(packetDiffers, ShouldEqual, false)
					})
				})
			})
		})
	})
}

func TestFlowReportingUptoFirstInvalidAck(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	SIP := net.IPv4zero
	packetDiffers := false

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {
			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error

			Convey("When I pass upto ACK packet with no token for Ack through the enforcer", func() {

				Convey("Then I expect the flow to be reported as rejected only once", func() {
					for k := 0; k < 2; k++ {
						if k == 0 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						}
						PacketFlow := packetgen.NewTemplateFlow()
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						for i := 0; i < PacketFlow.GetUptoFirstAckPacket().GetNumPackets(); i++ {
							start, err := PacketFlow.GetUptoFirstAckPacket().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, start, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}
							input, err := PacketFlow.GetUptoFirstAckPacket().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, input, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() {

								_, err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)

							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {

								_, err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)

							}

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() {

								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)

							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {

								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)

							}
							if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && !PacketFlow.GetNthPacket(i).GetTCPFin() {

								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldNotBeNil)

							}

							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}

							if !reflect.DeepEqual(oldPacket.GetTCPBytes(), outPacket.GetTCPBytes()) {
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
					}
					Convey("Then I expect all the input and output packets (after encoding and decoding) to be same", func() {

						So(packetDiffers, ShouldEqual, false)
					})
				})
			})
		})
	})
}

func TestFlowReportingUptoValidSynAck(t *testing.T) {

	ctrl := gomock.NewController(t)
	//Dummy Added to ensure ipset coreos does not fail
	ipset.New("temp_set", "hash:ip", &ipset.Params{}) // nolint: errcheck
	defer func() {
		//ips.Destroy()
		ctrl.Finish()

	}()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	SIP := net.IPv4zero
	packetDiffers := false

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {
			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error

			Convey("When I pass upto SynAck with no token for Syn through the enforcer", func() {

				Convey("Then I expect the flow to be reported only once", func() {
					for k := 0; k < 2; k++ {
						if k == 0 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						}

						PacketFlow := packetgen.NewTemplateFlow()
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						for i := 0; i < PacketFlow.GetUptoFirstAckPacket().GetNumPackets(); i++ {
							start, err := PacketFlow.GetUptoFirstAckPacket().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, start, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}
							input, err := PacketFlow.GetUptoFirstAckPacket().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, input, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}

							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {

								_, err = enforcer.processApplicationTCPPackets(tcpPacket)
								// The app synack packet will be considered as non PU traffic
								So(err, ShouldBeNil)
							}

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								contextID := "123456"
								puInfo := policy.NewPUInfo(contextID, common.LinuxProcessPU)
								context, err := pucontext.NewPU(contextID, puInfo, 10*time.Second)
								So(err, ShouldBeNil)
								enforcer.puFromContextID.AddOrUpdate(contextID, context)
								s, _ := portspec.NewPortSpec(80, 80, contextID)
								enforcer.contextIDFromTCPPort.AddPortSpec(s)

								_, err = enforcer.processApplicationTCPPackets(tcpPacket)
								// The app synack packet will be considered as non PU traffic
								So(err, ShouldNotBeNil)
							}

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() {

								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldNotBeNil)

							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)

							}

							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}
							if !reflect.DeepEqual(oldPacket.GetTCPBytes(), outPacket.GetTCPBytes()) {
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
					}
					Convey("Then I expect all the input and output packets (after encoding and decoding) to be same", func() {

						So(packetDiffers, ShouldEqual, false)
					})
				})
			})
		})
	})
}

func TestFlowReportingUptoValidAck(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ipset.New("temp_set", "hash:ip", &ipset.Params{}) // nolint: errcheck
	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	SIP := net.IPv4zero
	packetDiffers := false

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {
			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error

			Convey("When I pass upto ACK packet with no token for Syn and SynAck through the enforcer", func() {

				Convey("Then I expect the flow to be reported only once", func() {
					for k := 0; k < 2; k++ {
						if k == 0 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						}
						PacketFlow := packetgen.NewTemplateFlow()
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						for i := 0; i < PacketFlow.GetUptoFirstAckPacket().GetNumPackets(); i++ {
							start, err := PacketFlow.GetUptoFirstAckPacket().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, start, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}

							input, err := PacketFlow.GetUptoFirstAckPacket().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, input, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}

							if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && !PacketFlow.GetNthPacket(i).GetTCPFin() {

								_, err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							}

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() {

								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldNotBeNil)

							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)

							}
							if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && !PacketFlow.GetNthPacket(i).GetTCPFin() {

								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)

							}

							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}
						}
					}
					Convey("Then I expect all the input and output packets (after encoding and decoding) to be same", func() {

						So(packetDiffers, ShouldEqual, false)
					})
				})
			})
		})
	})
}

func TestReportingTwoGoodFlows(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	SIP := net.IPv4zero

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {
			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error

			Convey("When I pass multiple packets with delay of Syn after ack", func() {

				Convey("Then I expect the flow to be reported only once ", func() {

					for k := 0; k < 2; k++ {
						if k == 0 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						}
						PacketFlow := packetgen.NewTemplateFlow()
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						var isAckPacket bool
						for i := 0; i < 3; i++ {
							start, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, start, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}
							input, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, input, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() && isAckPacket {
								fmt.Println("This is App (A)", i)
								_, err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							} else {
								fmt.Println("This is App (B)", i)
								_, err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							}

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() && isAckPacket {
								fmt.Println("This is network (A)", i)
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							} else if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && isAckPacket {
								fmt.Println("This is network (B)", i)
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							} else {
								fmt.Println("This is network (C)", i)
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							}

							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}

							if isAckPacket {
								break
							}
							if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && !isAckPacket {
								i = -1
								isAckPacket = true
							}
						}
					}
				})
			})
		})
	})
}

func TestReportingTwoGoodFlowsUptoSynAck(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	SIP := net.IPv4zero

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {
			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error

			Convey("When I pass multiple packets with delay SynAck twice after Ack", func() {

				Convey("Then I expect the flow to be reported only once ", func() {

					for k := 0; k < 2; k++ {
						if k == 0 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						}
						PacketFlow := packetgen.NewTemplateFlow()
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						var isAckPacket bool

						for i := 0; i < 3; i++ {
							start, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, start, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}
							input, err := PacketFlow.GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, input, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() && isAckPacket {
								fmt.Println("This is App (A)", i)
								_, err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							} else if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && isAckPacket {
								fmt.Println("This is App (B)", i)
								_, err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							} else {
								fmt.Println("This is App (C)", i)
								_, err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							}

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() && isAckPacket {
								fmt.Println("This is network (A)", i)
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
								fmt.Println(err)
							} else if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && isAckPacket {
								fmt.Println("This is network (B)", i)
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							} else {
								fmt.Println("This is network (C)", i)
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							}

							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && isAckPacket {
								break
							}
							if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && !isAckPacket {
								i = -1
								isAckPacket = true
							}
						}
					}
				})
			})
		})
	})
}

func TestSynPacketWithInvalidAuthenticationOptionLength(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	SIP := net.IPv4zero

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {
			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error

			Convey("When I pass SYN packet with bad option length through the enforcer", func() {

				Convey("Then I expect the flow to be reported as rejected once", func() {
					for k := 0; k < 2; k++ {
						if k == 0 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = testSrcIP
							dstEndPoint.IP = testDstIP
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						}
						PacketFlow := packetgen.NewTemplateFlow()
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						for i := 0; i < PacketFlow.GetSynPackets().GetNumPackets(); i++ {

							start, err := PacketFlow.GetSynPackets().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, start, "0", true)
							oldPacket.Print(123456)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}

							input, err := PacketFlow.GetSynPackets().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, input, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}

							_, err = enforcer.processApplicationTCPPackets(tcpPacket)
							So(err, ShouldBeNil)

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)

							//changing the option length
							tcpBuffer := outPacket.GetBuffer(int(outPacket.IPHeaderLen()))
							tcpBuffer[outPacket.TCPDataStartBytes()-enforcerconstants.TCPAuthenticationOptionBaseLen] = 233

							err = outPacket.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen)
							So(err, ShouldNotBeNil)

							_, err = enforcer.processNetworkTCPPackets(outPacket)
							So(err, ShouldNotBeNil)

							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}
						}
					}
				})
			})
		})
	})
}

func TestSynAckPacketWithInvalidAuthenticationOptionLength(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	SIP := net.IPv4zero

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("Given I create a two processing unit instances", func() {
			var puInfo1, puInfo2 *policy.PUInfo
			var enforcer *Datapath
			var err1, err2 error

			Convey("When I pass upto SYNACK packet with bad option length through the enforcer", func() {

				Convey("Then I expect the flow to be reported as rejected once", func() {
					for k := 0; k < 2; k++ {
						if k == 0 {

							mockCollector.EXPECT().CollectFlowEvent(gomock.Any()).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							mockCollector.EXPECT().CollectFlowEvent(gomock.Any()).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)
						}
						PacketFlow := packetgen.NewTemplateFlow()
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
						So(err, ShouldBeNil)
						for i := 0; i < PacketFlow.GetUptoFirstSynAckPacket().GetNumPackets(); i++ {
							start, err := PacketFlow.GetUptoFirstSynAckPacket().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							oldPacket, err := packet.New(0, start, "0", true)
							if err == nil && oldPacket != nil {
								oldPacket.UpdateIPChecksum()
								oldPacket.UpdateTCPChecksum()
							}
							input, err := PacketFlow.GetUptoFirstSynAckPacket().GetNthPacket(i).ToBytes()
							So(err, ShouldBeNil)
							tcpPacket, err := packet.New(0, input, "0", true)
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
								SIP = tcpPacket.SourceAddress()
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
								t.Error("Invalid Test Packet")
							}

							_, err = enforcer.processApplicationTCPPackets(tcpPacket)
							So(err, ShouldBeNil)

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetTCPBytes()))
							copy(output, tcpPacket.GetTCPBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
							So(errp, ShouldBeNil)

							if PacketFlow.GetUptoFirstSynAckPacket().GetNthPacket(i).GetTCPSyn() && PacketFlow.GetUptoFirstSynAckPacket().GetNthPacket(i).GetTCPAck() {
								//changing the option length of SynAck packet
								tcpBuffer := outPacket.GetBuffer(int(outPacket.IPHeaderLen()))
								tcpBuffer[outPacket.TCPDataStartBytes()-enforcerconstants.TCPAuthenticationOptionBaseLen] = 233
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldNotBeNil)
							} else {
								_, err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							}
							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}
						}
					}
				})
			})
		})
	})
}

func TestPacketsWithInvalidTags(t *testing.T) {

	SIP := net.IPv4zero

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		Convey("When I pass a packet through the enforcer with invalid tags", func() {

			tagSelector := policy.TagSelector{

				Clause: []policy.KeyValueOperator{
					{
						Key:      enforcerconstants.TransmitterLabel,
						Value:    []string{"non-value"},
						Operator: policy.Equal,
					},
				},
				Policy: &policy.FlowPolicy{Action: policy.Accept},
			}
			PacketFlow := packetgen.NewTemplateFlow()
			_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
			So(err, ShouldBeNil)
			iteration = iteration + 1
			puID1 := "SomeProcessingUnitId" + string(iteration) + "1"
			puID2 := "SomeProcessingUnitId" + string(iteration) + "2"
			puIP1 := PacketFlow.GetNthPacket(0).GetIPPacket().SrcIP.String() // + strconv.Itoa(iteration)
			puIP2 := PacketFlow.GetNthPacket(0).GetIPPacket().DstIP.String() // + strconv.Itoa(iteration)
			serverID := testServerID

			// Create ProcessingUnit 1
			puInfo1 := policy.NewPUInfo(puID1, common.ContainerPU)

			ip1 := policy.ExtendedMap{}
			ip1["bridge"] = puIP1
			puInfo1.Runtime.SetIPAddresses(ip1)
			ipl1 := policy.ExtendedMap{policy.DefaultNamespace: puIP1}
			puInfo1.Policy.SetIPAddresses(ipl1)
			puInfo1.Policy.AddIdentityTag(enforcerconstants.TransmitterLabel, "value")
			puInfo1.Policy.AddReceiverRules(tagSelector)

			// Create processing unit 2
			puInfo2 := policy.NewPUInfo(puID2, common.ContainerPU)
			ip2 := policy.ExtendedMap{"bridge": puIP2}
			puInfo2.Runtime.SetIPAddresses(ip2)
			ipl2 := policy.ExtendedMap{policy.DefaultNamespace: puIP2}
			puInfo2.Policy.SetIPAddresses(ipl2)
			puInfo2.Policy.AddIdentityTag(enforcerconstants.TransmitterLabel, "value")
			puInfo2.Policy.AddReceiverRules(tagSelector)

			secret, err := secrets.NewCompactPKI([]byte(secrets.PrivateKeyPEM), []byte(secrets.PublicPEM), []byte(secrets.CAPEM), secrets.CreateTxtToken(), claimsheader.CompressionTypeNone)
			So(err, ShouldBeNil)
			collector := &collector.DefaultCollector{}
			// mock the call
			prevRawSocket := GetUDPRawSocket
			defer func() {
				GetUDPRawSocket = prevRawSocket
			}()
			GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
				return nil, nil
			}
			enforcer := NewWithDefaults(serverID, collector, nil, secret, constants.RemoteContainer, "/proc", []string{"0.0.0.0/0"})
			err1 := enforcer.Enforce(puID1, puInfo1)
			err2 := enforcer.Enforce(puID2, puInfo2)
			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)

			for i := 0; i < PacketFlow.GetSynPackets().GetNumPackets(); i++ {
				start, err := PacketFlow.GetSynPackets().GetNthPacket(i).ToBytes()
				So(err, ShouldBeNil)
				oldPacket, err := packet.New(0, start, "0", true)
				if err == nil && oldPacket != nil {
					oldPacket.UpdateIPChecksum()
					oldPacket.UpdateTCPChecksum()
				}

				input, err := PacketFlow.GetSynPackets().GetNthPacket(i).ToBytes()
				So(err, ShouldBeNil)
				tcpPacket, err := packet.New(0, input, "0", true)
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
					SIP = tcpPacket.SourceAddress()
				}
				if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
					!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
					t.Error("Invalid Test Packet")
				}
				_, err = enforcer.processApplicationTCPPackets(tcpPacket)
				So(err, ShouldBeNil)

				if debug {
					fmt.Println("Intermediate packet", i)
					tcpPacket.Print(0)
				}

				output := make([]byte, len(tcpPacket.GetTCPBytes()))
				copy(output, tcpPacket.GetTCPBytes())

				outPacket, errp := packet.New(0, output, "0", true)
				So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
				So(errp, ShouldBeNil)

				_, err = enforcer.processNetworkTCPPackets(outPacket)
				So(err, ShouldNotBeNil)

				if debug {
					fmt.Println("Output packet", i)
					outPacket.Print(0)
				}
			}
		})
	})
}

func TestForPacketsWithRandomFlags(t *testing.T) {

	SIP := net.IPv4zero

	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

		var puInfo1, puInfo2 *policy.PUInfo
		var enforcer *Datapath
		var err1, err2 error

		Convey("When I pass multiple packets with random flags through the enforcer", func() {

			Convey("Then I should not see any error", func() {
				for k := 0; k < 2; k++ {
					if k == 0 {
						tagSelector := policy.TagSelector{

							Clause: []policy.KeyValueOperator{
								{
									Key:      enforcerconstants.TransmitterLabel,
									Value:    []string{"value"},
									Operator: policy.Equal,
								},
							},
							Policy: &policy.FlowPolicy{Action: policy.Accept},
						}
						PacketFlow := packetgen.NewPacketFlow("aa:ff:aa:ff:aa:ff", "ff:aa:ff:aa:ff:aa", testSrcIP, testDstIP, 666, 80)
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGenerateGoodFlow)
						So(err, ShouldBeNil)
						iteration = iteration + 1
						puID1 := "SomeProcessingUnitId" + string(iteration) + "1"
						puID2 := "SomeProcessingUnitId" + string(iteration) + "2"
						puIP1 := testDstIP // + strconv.Itoa(iteration)
						puIP2 := testSrcIP // + strconv.Itoa(iteration)
						serverID := testServerID

						// Create ProcessingUnit 1
						puInfo1 = policy.NewPUInfo(puID1, common.ContainerPU)

						ip1 := policy.ExtendedMap{}
						ip1["bridge"] = puIP1
						puInfo1.Runtime.SetIPAddresses(ip1)
						ipl1 := policy.ExtendedMap{policy.DefaultNamespace: puIP1}
						puInfo1.Policy.SetIPAddresses(ipl1)
						puInfo1.Policy.AddIdentityTag(enforcerconstants.TransmitterLabel, "value")
						puInfo1.Policy.AddReceiverRules(tagSelector)

						// Create processing unit 2
						puInfo2 = policy.NewPUInfo(puID2, common.ContainerPU)
						ip2 := policy.ExtendedMap{"bridge": puIP2}
						puInfo2.Runtime.SetIPAddresses(ip2)
						ipl2 := policy.ExtendedMap{policy.DefaultNamespace: puIP2}
						puInfo2.Policy.SetIPAddresses(ipl2)
						puInfo2.Policy.AddIdentityTag(enforcerconstants.TransmitterLabel, "value")
						puInfo2.Policy.AddReceiverRules(tagSelector)

						secret, err := secrets.NewCompactPKI([]byte(secrets.PrivateKeyPEM), []byte(secrets.PublicPEM), []byte(secrets.CAPEM), secrets.CreateTxtToken(), claimsheader.CompressionTypeNone)
						So(err, ShouldBeNil)
						collector := &collector.DefaultCollector{}
						// mock the call
						prevRawSocket := GetUDPRawSocket
						defer func() {
							GetUDPRawSocket = prevRawSocket
						}()
						GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
							return nil, nil
						}
						enforcer = NewWithDefaults(serverID, collector, nil, secret, constants.RemoteContainer, "/proc", []string{"0.0.0.0/0"})
						err1 = enforcer.Enforce(puID1, puInfo1)
						err2 = enforcer.Enforce(puID2, puInfo2)
						So(puInfo1, ShouldNotBeNil)
						So(puInfo2, ShouldNotBeNil)
						So(enforcer, ShouldNotBeNil)
						So(err1, ShouldBeNil)
						So(err2, ShouldBeNil)

					} else if k == 1 {
						tagSelector := policy.TagSelector{

							Clause: []policy.KeyValueOperator{
								{
									Key:      enforcerconstants.TransmitterLabel,
									Value:    []string{"value"},
									Operator: policy.Equal,
								},
							},
							Policy: &policy.FlowPolicy{Action: policy.Accept},
						}
						PacketFlow := packetgen.NewPacketFlow("aa:ff:aa:ff:aa:ff", "ff:aa:ff:aa:ff:aa", testSrcIP, testDstIP, 666, 80)
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGenerateGoodFlow)
						So(err, ShouldBeNil)
						iteration = iteration + 1
						puID1 := "SomeProcessingUnitId" + string(iteration) + "1"
						puID2 := "SomeProcessingUnitId" + string(iteration) + "2"
						puIP1 := testDstIP // + strconv.Itoa(iteration)
						puIP2 := testSrcIP // + strconv.Itoa(iteration)
						serverID := testServerID

						// Create ProcessingUnit 1
						puInfo1 = policy.NewPUInfo(puID1, common.ContainerPU)

						ip1 := policy.ExtendedMap{}
						ip1["bridge"] = puIP1
						puInfo1.Runtime.SetIPAddresses(ip1)
						ipl1 := policy.ExtendedMap{policy.DefaultNamespace: puIP1}
						puInfo1.Policy.SetIPAddresses(ipl1)
						puInfo1.Policy.AddIdentityTag(enforcerconstants.TransmitterLabel, "value")
						puInfo1.Policy.AddReceiverRules(tagSelector)

						// Create processing unit 2
						puInfo2 = policy.NewPUInfo(puID2, common.ContainerPU)
						ip2 := policy.ExtendedMap{"bridge": puIP2}
						puInfo2.Runtime.SetIPAddresses(ip2)
						ipl2 := policy.ExtendedMap{policy.DefaultNamespace: puIP2}
						puInfo2.Policy.SetIPAddresses(ipl2)
						puInfo2.Policy.AddIdentityTag(enforcerconstants.TransmitterLabel, "value")
						puInfo2.Policy.AddReceiverRules(tagSelector)

						secret, err := secrets.NewCompactPKI([]byte(secrets.PrivateKeyPEM), []byte(secrets.PublicPEM), []byte(secrets.CAPEM), secrets.CreateTxtToken(), claimsheader.CompressionTypeNone)
						So(err, ShouldBeNil)
						collector := &collector.DefaultCollector{}

						// mock the call
						prevRawSocket := GetUDPRawSocket
						defer func() {
							GetUDPRawSocket = prevRawSocket
						}()
						GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
							return nil, nil
						}
						enforcer = NewWithDefaults(serverID, collector, nil, secret, constants.LocalServer, "/proc", []string{"0.0.0.0/0"})
						err1 = enforcer.Enforce(puID1, puInfo1)
						err2 = enforcer.Enforce(puID2, puInfo2)

					}
					PacketFlow := packetgen.NewPacketFlow("aa:ff:aa:ff:aa:ff", "ff:aa:ff:aa:ff:aa", testSrcIP, testDstIP, 666, 80)
					_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGenerateGoodFlow)
					So(err, ShouldBeNil)
					for i := 0; i < PacketFlow.GetNumPackets(); i++ {
						//Setting random TCP flags for all the packets
						PacketFlow.GetNthPacket(i).SetTCPCwr()
						PacketFlow.GetNthPacket(i).SetTCPPsh()
						PacketFlow.GetNthPacket(i).SetTCPEce()
						start, err := PacketFlow.GetNthPacket(i).ToBytes()
						So(err, ShouldBeNil)
						oldPacket, err := packet.New(0, start, "0", true)
						if err == nil && oldPacket != nil {
							oldPacket.UpdateIPChecksum()
							oldPacket.UpdateTCPChecksum()
						}
						input, err := PacketFlow.GetNthPacket(i).ToBytes()
						So(err, ShouldBeNil)
						tcpPacket, err := packet.New(0, input, "0", true)
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
							SIP = tcpPacket.SourceAddress()
						}
						if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
							!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
							t.Error("Invalid Test Packet")
						}

						_, err = enforcer.processApplicationTCPPackets(tcpPacket)
						So(err, ShouldBeNil)

						if debug {
							fmt.Println("Intermediate packet", i)
							tcpPacket.Print(0)
						}

						output := make([]byte, len(tcpPacket.GetTCPBytes()))
						copy(output, tcpPacket.GetTCPBytes())

						outPacket, errp := packet.New(0, output, "0", true)
						So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
						So(errp, ShouldBeNil)

						_, err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

						if debug {
							fmt.Println("Output packet", i)
							outPacket.Print(0)
						}
					}
				}
			})
		})
	})
}

func TestDNS(t *testing.T) {
	externalFQDN := "google.com"
	var err1, err2 error
	var lock sync.Mutex

	Convey("Given an initialized enforcer for Linux container", t, func() {
		secret, err := secrets.NewCompactPKI([]byte(secrets.PrivateKeyPEM), []byte(secrets.PublicPEM), []byte(secrets.CAPEM), secrets.CreateTxtToken(), claimsheader.CompressionTypeNone)
		So(err, ShouldBeNil)
		collector := &collector.DefaultCollector{}

		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		err1 = fmt.Errorf("net lookup not called")
		// mock the call
		origLookupHost := pucontext.LookupHost
		defer func() {
			pucontext.LookupHost = origLookupHost
		}()

		pucontext.LookupHost = func(name string) ([]string, error) {
			defer lock.Unlock()
			lock.Lock()
			if name == externalFQDN {
				err1 = nil
				return []string{testDstIP}, nil
			}

			return nil, fmt.Errorf("Error")
		}

		puID1 := "SomePU"
		enforcer := NewWithDefaults(testServerID, collector, nil, secret, constants.RemoteContainer, "/proc", []string{"1.1.1.1/31"})
		enforcer.packetLogs = true
		puInfo := policy.NewPUInfo(puID1, common.ContainerPU)
		puInfo.Policy.UpdateDNSNetworks([]policy.DNSRule{{
			Name:     externalFQDN,
			Port:     "80",
			Protocol: constants.TCPProtoNum,
			Policy:   &policy.FlowPolicy{Action: policy.Accept},
		}})

		err2 = enforcer.Enforce(puID1, puInfo)
		time.Sleep(5 * time.Second)
		defer lock.Unlock()
		lock.Lock()
		So(err1, ShouldBeNil)
		So(err2, ShouldBeNil)

		PacketFlow := packetgen.NewPacketFlow("aa:ff:aa:ff:aa:ff", "ff:aa:ff:aa:ff:aa", testSrcIP, "10.0.0.0", 666, 80)
		_, err = PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
		So(err, ShouldBeNil)

		synPacket, err := PacketFlow.GetFirstSynPacket().ToBytes()
		So(err, ShouldBeNil)

		tcpPacket, err := packet.New(0, synPacket, "0", true)
		if err == nil && tcpPacket != nil {
			tcpPacket.UpdateIPChecksum()
			tcpPacket.UpdateTCPChecksum()
		}
		_, err1 := enforcer.processApplicationTCPPackets(tcpPacket)
		So(err1, ShouldBeNil)
	})
}

func TestDNSWithError(t *testing.T) {
	externalFQDN := "google.com"
	var err1, err2, err3 error
	var lock sync.Mutex

	Convey("Given an initialized enforcer for Linux container", t, func() {
		secret, err := secrets.NewCompactPKI([]byte(secrets.PrivateKeyPEM), []byte(secrets.PublicPEM), []byte(secrets.CAPEM), secrets.CreateTxtToken(), claimsheader.CompressionTypeNone)
		So(err, ShouldBeNil)
		collector := &collector.DefaultCollector{}

		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		err1 = fmt.Errorf("net lookup not called")
		err3 = fmt.Errorf("Error")
		// mock the call
		origLookupHost := pucontext.LookupHost
		defer func() {
			pucontext.LookupHost = origLookupHost
		}()

		firstCall := 0
		pucontext.LookupHost = func(name string) ([]string, error) {
			defer lock.Unlock()
			lock.Lock()
			if firstCall < 3 {
				err3 = nil
				firstCall++
				return nil, fmt.Errorf("Error")
			}

			if name == externalFQDN {
				fmt.Println("return nil")
				err1 = nil
				return []string{testDstIP}, nil
			}

			return nil, fmt.Errorf("Error")
		}

		puID1 := "SomePU"
		enforcer := NewWithDefaults(testServerID, collector, nil, secret, constants.RemoteContainer, "/proc", []string{"1.1.1.1/31"})
		enforcer.packetLogs = true
		puInfo := policy.NewPUInfo(puID1, common.ContainerPU)
		puInfo.Policy.UpdateDNSNetworks([]policy.DNSRule{{
			Name:     externalFQDN,
			Port:     "80",
			Protocol: constants.TCPProtoNum,
			Policy:   &policy.FlowPolicy{Action: policy.Accept},
		}})

		err2 = enforcer.Enforce(puID1, puInfo)
		time.Sleep(12 * time.Second)
		defer lock.Unlock()
		lock.Lock()
		So(err1, ShouldBeNil)
		So(err2, ShouldBeNil)
		So(err3, ShouldBeNil)

		PacketFlow := packetgen.NewPacketFlow("aa:ff:aa:ff:aa:ff", "ff:aa:ff:aa:ff:aa", testSrcIP, "10.0.0.0", 666, 80)
		_, err = PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
		So(err, ShouldBeNil)

		synPacket, err := PacketFlow.GetFirstSynPacket().ToBytes()
		So(err, ShouldBeNil)

		tcpPacket, err := packet.New(0, synPacket, "0", true)
		if err == nil && tcpPacket != nil {
			tcpPacket.UpdateIPChecksum()
			tcpPacket.UpdateTCPChecksum()
		}
		_, err1 := enforcer.processApplicationTCPPackets(tcpPacket)
		So(err1, ShouldBeNil)
	})
}

func TestPUPortCreation(t *testing.T) {
	Convey("Given an initialized enforcer for Linux Processes", t, func() {
		secret, err := secrets.NewCompactPKI([]byte(secrets.PrivateKeyPEM), []byte(secrets.PublicPEM), []byte(secrets.CAPEM), secrets.CreateTxtToken(), claimsheader.CompressionTypeNone)
		So(err, ShouldBeNil)
		collector := &collector.DefaultCollector{}

		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		lock.Lock()
		readFiles = mockfiles
		lock.Unlock()

		enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.LocalServer, "/proc", []string{"0.0.0.0/0"})
		enforcer.packetLogs = true
		enforcer.mode = constants.LocalServer

		enforcer.mode = constants.LocalServer
		contextID := "1001"
		puInfo := policy.NewPUInfo(contextID, common.LinuxProcessPU)
		puInfo.Runtime.SetOptions(policy.OptionsType{
			CgroupMark: "100",
		})

		enforcer.Enforce(contextID, puInfo) // nolint

	})
}

func TestCollectTCPPacket(t *testing.T) {
	//setup a default debug message
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	var puInfo1 *policy.PUInfo
	var enforcer *Datapath
	var err1, err2 error
	mockCollector := mockcollector.NewMockEventCollector(ctrl)
	Convey("Given an initialiazed debug message", t, func() {
		puInfo1, _, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, "container", false)
		So(enforcer, ShouldNotBeNil)
		So(err1, ShouldBeNil)
		So(err2, ShouldBeNil)
		PacketFlow := packetgen.NewTemplateFlow()
		_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
		So(err, ShouldBeNil)

		synPacket, err := PacketFlow.GetFirstSynPacket().ToBytes()
		So(err, ShouldBeNil)

		tcpPacket, err := packet.New(0, synPacket, "0", true)
		So(err, ShouldBeNil)
		Convey("We setup tcp network packet tracing for this pu with incomplete state", func() {
			interval := 10 * time.Second
			err := enforcer.EnableDatapathPacketTracing(puInfo1.ContextID, packettracing.NetworkOnly, interval)
			So(err, ShouldBeNil)
			packetreport := collector.PacketReport{
				DestinationIP: tcpPacket.DestinationAddress().String(),
				SourceIP:      tcpPacket.SourceAddress().String(),
			}
			mockCollector.EXPECT().CollectPacketEvent(PacketEventMatcher(&packetreport)).Times(0)
			enforcer.collectTCPPacket(&debugpacketmessage{
				Mark:    10,
				p:       tcpPacket,
				tcpConn: nil,
				udpConn: nil,
				err:     nil,
				network: true,
			})
		})
		Convey("We setup tcp network packet tracing for this pu with tcpConn != nil state", func() {
			interval := 10 * time.Second
			err := enforcer.EnableDatapathPacketTracing(puInfo1.ContextID, packettracing.NetworkOnly, interval)
			So(err, ShouldBeNil)
			packetreport := collector.PacketReport{
				DestinationIP: tcpPacket.DestinationAddress().String(),
				SourceIP:      tcpPacket.SourceAddress().String(),
			}
			context, _ := enforcer.puFromContextID.Get(puInfo1.ContextID)
			tcpConn := connection.NewTCPConnection(context.(*pucontext.PUContext), nil)
			mockCollector.EXPECT().CollectPacketEvent(PacketEventMatcher(&packetreport)).Times(1)
			enforcer.collectTCPPacket(&debugpacketmessage{
				Mark:    10,
				p:       tcpPacket,
				tcpConn: tcpConn,
				udpConn: nil,
				err:     nil,
				network: true,
			})
		})
		Convey("We setup tcp network packet tracing for this pu with tcpConn != nil and inject application packet", func() {
			interval := 10 * time.Second
			err := enforcer.EnableDatapathPacketTracing(puInfo1.ContextID, packettracing.NetworkOnly, interval)
			So(err, ShouldBeNil)
			packetreport := collector.PacketReport{
				DestinationIP: tcpPacket.DestinationAddress().String(),
				SourceIP:      tcpPacket.SourceAddress().String(),
			}
			context, _ := enforcer.puFromContextID.Get(puInfo1.ContextID)
			tcpConn := connection.NewTCPConnection(context.(*pucontext.PUContext), nil)
			mockCollector.EXPECT().CollectPacketEvent(PacketEventMatcher(&packetreport)).Times(0)
			enforcer.collectTCPPacket(&debugpacketmessage{
				Mark:    10,
				p:       tcpPacket,
				tcpConn: tcpConn,
				udpConn: nil,
				err:     nil,
				network: false,
			})
		})

	})
}

func TestEnableDatapathPacketTracing(t *testing.T) {
	Convey("Given i setup a valid enforcer and a processing unit", t, func() {
		puInfo1, _, enforcer, err1, err2, _, _ := setupProcessingUnitsInDatapathAndEnforce(nil, "container", true)
		So(err1, ShouldBeNil)
		So(err2, ShouldBeNil)
		Convey("I enable packettracing on a PU", func() {
			err := enforcer.EnableDatapathPacketTracing(puInfo1.ContextID, packettracing.ApplicationOnly, 10*time.Second)
			So(err, ShouldBeNil)
			_, err = enforcer.packetTracingCache.Get(puInfo1.ContextID)
			So(err, ShouldBeNil)
		})
	})
}

type testFiles struct{}

var mockfiles *testFiles

func (f *testFiles) readProcNetTCP() (inodeMap map[string]string, userMap map[string]map[string]bool, err error) {
	inodeMap = map[string]string{}
	userMap = map[string]map[string]bool{}

	inodeMap["12345"] = "80"
	return
}

func (f *testFiles) readOpenSockFD(pid string) []string {
	if pid == "1002" {
		return []string{"12345"}
	}

	return []string{}
}

func (f *testFiles) getCgroupList() []string {
	return []string{"1001"}
}

func (f *testFiles) listCgroupProcesses(cgroupname string) ([]string, error) {
	return []string{"1002", "1003"}, nil
}
