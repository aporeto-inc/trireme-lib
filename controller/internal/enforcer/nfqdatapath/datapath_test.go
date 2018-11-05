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
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/packetgen"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/portspec"
)

var (
	debug     bool
	iteration int
)

func TestEnforcerExternalNetworks(t *testing.T) {
	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {
		var enforcer *Datapath
		var err1, err2 error
		Convey("Given I create a two processing unit instances", func() {
			_, _, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, false, "container", true)
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
				err1 := enforcer.processApplicationTCPPackets(tcpPacket)
				So(err1, ShouldNotBeNil)
			})
		})
	})
}

func TestInvalidContext(t *testing.T) {

	Convey("Given I create a new enforcer instance", t, func() {

		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
		collector := &collector.DefaultCollector{}

		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.LocalServer, "/proc", []string{"0.0.0.0/0"})
		PacketFlow := packetgen.NewTemplateFlow()
		_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
		So(err, ShouldBeNil)
		synPacket, err := PacketFlow.GetFirstSynPacket().ToBytes()
		So(err, ShouldBeNil)
		tcpPacket, err := packet.New(0, synPacket, "0", true)

		Convey("When I run a TCP Syn packet through a non existing context", func() {

			err1 := enforcer.processApplicationTCPPackets(tcpPacket)
			err2 := enforcer.processNetworkTCPPackets(tcpPacket)

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

		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
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

		enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.LocalServer, "/proc", []string{"0.0.0.0/0"})
		Convey("Then enforcer instance must be initialized", func() {
			So(enforcer, ShouldNotBeNil)
		})

		enforcer.Enforce("SomeServerId", puInfo) // nolint
		defer func() {
			if err := enforcer.Unenforce("SomeServerId"); err != nil {
				fmt.Println("Error", err.Error())
			}
		}()
		PacketFlow := packetgen.NewTemplateFlow()
		_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeMultipleGoodFlow)
		So(err, ShouldBeNil)
		synPacket, err := PacketFlow.GetFirstSynPacket().ToBytes()
		So(err, ShouldBeNil)
		tcpPacket, err := packet.New(0, synPacket, "0", true)

		Convey("When I run a TCP Syn packet through an invalid existing context (missing IP)", func() {

			err1 := enforcer.processApplicationTCPPackets(tcpPacket)
			err2 := enforcer.processNetworkTCPPackets(tcpPacket)

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
			puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, false, "container", false)
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

				err1 := enforcer.processApplicationTCPPackets(tcpPacket)

				// Test whether the packet is modified with Fin/Ack
				if tcpPacket.TCPFlags != 0x11 {
					t.Fail()
				}

				err2 := enforcer.processNetworkTCPPackets(&tcpPacketCopy)

				if tcpPacket.TCPFlags != 0x11 {
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

		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
		puInfo := policy.NewPUInfo("SomeProcessingUnitId", common.LinuxProcessPU)

		PacketFlow := packetgen.NewTemplateFlow()
		_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
		So(err, ShouldBeNil)
		ip := policy.ExtendedMap{
			"brige": "164.67.228.152",
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

		enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.LocalServer, "/proc", []string{"0.0.0.0/0"})
		enforcer.Enforce("SomeServerId", puInfo) // nolint

		synPacket, err := PacketFlow.GetFirstSynPacket().ToBytes()
		So(err, ShouldBeNil)
		tcpPacket, err := packet.New(0, synPacket, "0", true)

		Convey("When I run a TCP Syn packet through an invalid existing context (missing IP)", func() {

			err1 := enforcer.processApplicationTCPPackets(tcpPacket)
			err2 := enforcer.processNetworkTCPPackets(tcpPacket)

			Convey("Then I should see an error for missing Token", func() {

				So(err, ShouldBeNil)
				So(err1, ShouldNotBeNil)
				So(err2, ShouldBeNil)
			})
		})
	})
}

type myMatcher struct {
	x interface{}
}

func (m *myMatcher) Matches(x interface{}) bool {
	f1 := m.x.(*collector.FlowRecord)
	f2 := x.(*collector.FlowRecord)

	if f1.Destination.IP == f2.Destination.IP && f1.Source.IP == f2.Source.IP && f1.Destination.Port == f2.Destination.Port && f1.Action == f2.Action && f1.Count == f2.Count {

		return true
	}

	return false
}

func (m *myMatcher) String() string {
	return fmt.Sprintf("is equal to %T", m.x)
}

func MyMatcher(x interface{}) gomock.Matcher {
	return &myMatcher{x: x}
}

func setupProcessingUnitsInDatapathAndEnforce(collectors *mockcollector.MockEventCollector, multiFlows bool, modeType string, targetNetExternal bool) (puInfo1, puInfo2 *policy.PUInfo, enforcer *Datapath, err1, err2, err3, err4 error) {
	var mode constants.ModeType
	if modeType == "container" {
		mode = constants.RemoteContainer
	} else if modeType == "server" {
		mode = constants.LocalServer
	}
	if !multiFlows {
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
		serverID := "SomeServerId"

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

		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
		if collectors != nil {
			// mock the call
			prevRawSocket := GetUDPRawSocket
			defer func() {
				GetUDPRawSocket = prevRawSocket
			}()
			GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
				return nil, nil
			}
			if targetNetExternal == true {
				enforcer = NewWithDefaults(serverID, collectors, nil, secret, mode, "/proc", []string{"1.1.1.1/31"})
			} else {
				enforcer = NewWithDefaults(serverID, collectors, nil, secret, mode, "/proc", []string{"0.0.0.0/0"})
			}

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

			if targetNetExternal == true {
				enforcer = NewWithDefaults(serverID, collector, nil, secret, mode, "/proc", []string{"1.1.1.1/31"})
			} else {
				enforcer = NewWithDefaults(serverID, collector, nil, secret, mode, "/proc", []string{"0.0.0.0/0"})
			}
			err1 = enforcer.Enforce(puID1, puInfo1)
			err2 = enforcer.Enforce(puID2, puInfo2)
		}

		return puInfo1, puInfo2, enforcer, err1, err2, nil, nil
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
	_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeMultipleIntervenedFlow)
	So(err, ShouldBeNil)
	iteration = iteration + 1
	puID1 := "SomeProcessingUnitId" + string(iteration) + "1"
	puID2 := "SomeProcessingUnitId" + string(iteration) + "2"
	puID3 := "SomeProcessingUnitId" + string(iteration) + "3"
	puID4 := "SomeProcessingUnitId" + string(iteration) + "4"

	var puIP1, puIP2, puIP3, puIP4 string

	for j := 0; j < PacketFlow.GetNumPackets(); j++ {
		if PacketFlow.GetNthPacket(j).GetIPPacket().SrcIP.String() == "10.1.10.76" || PacketFlow.GetNthPacket(j).GetIPPacket().DstIP.String() == "10.1.10.76" {
			puIP1 = "10.1.10.76"     // + strconv.Itoa(iteration)
			puIP2 = "164.67.228.152" // + strconv.Itoa(iteration)
		} else {
			puIP3 = "192.168.1.2"     // + strconv.Itoa(iteration)
			puIP4 = "174.143.213.184" // + strconv.Itoa(iteration)
		}
	}
	serverID := "SomeServerId"

	// Create ProcessingUnit 1
	puInfo1 = policy.NewPUInfo(puID1, common.ContainerPU)

	ip1 := policy.ExtendedMap{}
	ip1["bridge"] = puIP1
	puInfo1.Runtime.SetIPAddresses(ip1)
	ipl1 := policy.ExtendedMap{policy.DefaultNamespace: puIP1, "proxyPort": "5000"}
	puInfo1.Policy.SetIPAddresses(ipl1)
	puInfo1.Policy.AddIdentityTag(enforcerconstants.TransmitterLabel, "value")
	puInfo1.Policy.AddReceiverRules(tagSelector)

	// Create processing unit 2
	puInfo2 = policy.NewPUInfo(puID2, common.ContainerPU)
	ip2 := policy.ExtendedMap{"bridge": puIP2, "proxyPort": "5001"}
	puInfo2.Runtime.SetIPAddresses(ip2)
	ipl2 := policy.ExtendedMap{policy.DefaultNamespace: puIP2, "proxyPort": "5002"}
	puInfo2.Policy.SetIPAddresses(ipl2)
	puInfo2.Policy.AddIdentityTag(enforcerconstants.TransmitterLabel, "value")
	puInfo2.Policy.AddReceiverRules(tagSelector)

	// Create processing unit 3
	puInfo3 := policy.NewPUInfo(puID3, common.ContainerPU)
	ip3 := policy.ExtendedMap{policy.DefaultNamespace: puIP2, "proxyPort": "5003"}
	puInfo3.Runtime.SetIPAddresses(ip3)
	ipl3 := policy.ExtendedMap{policy.DefaultNamespace: puIP3, "proxyPort": "5004"}
	puInfo3.Policy.SetIPAddresses(ipl3)
	puInfo3.Policy.AddIdentityTag(enforcerconstants.TransmitterLabel, "value")
	puInfo3.Policy.AddReceiverRules(tagSelector)

	// Create processing unit 4
	puInfo4 := policy.NewPUInfo(puID4, common.ContainerPU)
	ip4 := policy.ExtendedMap{policy.DefaultNamespace: puIP4}
	puInfo4.Runtime.SetIPAddresses(ip4)
	ipl4 := policy.ExtendedMap{policy.DefaultNamespace: puIP4}
	puInfo4.Policy.SetIPAddresses(ipl4)
	puInfo4.Policy.AddIdentityTag(enforcerconstants.TransmitterLabel, "value")
	puInfo4.Policy.AddReceiverRules(tagSelector)

	secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
	if collectors != nil {
		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}
		enforcer = NewWithDefaults(serverID, collectors, nil, secret, mode, "/proc", []string{"0.0.0.0/0"})
		err1 = enforcer.Enforce(puID1, puInfo1)
		err2 = enforcer.Enforce(puID2, puInfo2)
		err3 = enforcer.Enforce(puID3, puInfo3)
		err4 = enforcer.Enforce(puID4, puInfo4)
	} else {

		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}
		collector := &collector.DefaultCollector{}
		enforcer = NewWithDefaults(serverID, collector, nil, secret, mode, "/proc", []string{"0.0.0.0/0"})
		err1 = enforcer.Enforce(puID1, puInfo1)
		err2 = enforcer.Enforce(puID2, puInfo2)
		err3 = enforcer.Enforce(puID3, puInfo3)
		err4 = enforcer.Enforce(puID4, puInfo4)
	}

	return puInfo1, puInfo2, enforcer, err1, err2, err3, err4
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

						puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, false, "container", false)
						So(puInfo1, ShouldNotBeNil)
						So(puInfo2, ShouldNotBeNil)
						So(err1, ShouldBeNil)
						So(err2, ShouldBeNil)

					} else if k == 1 {

						puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, false, "server", false)
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

						outPacket, errp := packet.New(0, output, "0", true)
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

						puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, false, "container", false)
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

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
							So(errp, ShouldBeNil)

							err = enforcer.processNetworkTCPPackets(outPacket)
							So(err, ShouldBeNil)

							if debug {
								fmt.Println("Output packet", i)
								outPacket.Print(0)
							}
						}
					} else if k == 1 {

						puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, false, "server", false)
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
								Convey("When I pass a packet with SYN or SYN/ACK flags for packet (server) "+string(i), func() {
									Convey("Then I expect some data payload to exist on the packet (server)"+string(i), func() {
										// In our 3 way security handshake syn and syn-ack packet should grow in length
										So(tcpPacket.IPTotalLength, ShouldBeGreaterThan, oldPacket.IPTotalLength)
									})
								})
							}

							if !firstSynAckProcessed && tcpPacket.TCPFlags&packet.TCPSynAckMask == packet.TCPAckMask {
								firstSynAckProcessed = true
								Convey("When I pass the first packet with ACK flag for packet (server)"+string(i), func() {
									Convey("Then I expect some data payload to exist on the packet (server)"+string(i), func() {
										// In our 3 way security handshake first ack packet should grow in length
										So(tcpPacket.IPTotalLength, ShouldBeGreaterThan, oldPacket.IPTotalLength)
									})
								})
							}

							output := make([]byte, len(tcpPacket.GetBytes()))
							copy(output, tcpPacket.GetBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
							So(errp, ShouldBeNil)

							err = enforcer.processNetworkTCPPackets(outPacket)
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

			puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, false, "server", false)
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

					outPacket, errp := packet.New(0, output, "0", true)
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
		var puInfo1, puInfo2 *policy.PUInfo
		var enforcer *Datapath
		var err1, err2 error
		Convey("Given I create a two processing unit instances", func() {

			for k := 0; k < 2; k++ {
				if k == 0 {

					puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, false, "container", false)
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

						err = enforcer.processApplicationTCPPackets(tcpPacket)
						//After sending syn packet
						CheckAfterAppSynPacket(enforcer, tcpPacket)
						So(err, ShouldBeNil)
						output := make([]byte, len(tcpPacket.GetBytes()))
						copy(output, tcpPacket.GetBytes())

						outPacket, err := packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						err = enforcer.processNetworkTCPPackets(outPacket)
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
						err = enforcer.processApplicationTCPPackets(tcpPacket)
						So(err, ShouldBeNil)

						output := make([]byte, len(tcpPacket.GetBytes()))
						copy(output, tcpPacket.GetBytes())

						outPacket, err := packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						outPacket.Print(0)
						err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

						//Now lets send the synack packet from the server in response
						input, err = PacketFlow.GetFirstSynAckPacket().ToBytes()
						So(err, ShouldBeNil)

						tcpPacket, err = packet.New(0, input, "0", true)
						if err == nil && tcpPacket != nil {
							tcpPacket.UpdateIPChecksum()
							tcpPacket.UpdateTCPChecksum()
						}
						err = enforcer.processApplicationTCPPackets(tcpPacket)
						So(err, ShouldBeNil)

						output = make([]byte, len(tcpPacket.GetBytes()))
						copy(output, tcpPacket.GetBytes())

						outPacket, err = packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						outPacketcopy, _ := packet.New(0, output, "0", true)
						err = enforcer.processNetworkTCPPackets(outPacket)
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
						err = enforcer.processApplicationTCPPackets(tcpPacket)
						So(err, ShouldBeNil)

						output := make([]byte, len(tcpPacket.GetBytes()))
						copy(output, tcpPacket.GetBytes())

						outPacket, err := packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

						//Now lets send the synack packet from the server in response
						input, err = PacketFlow.GetFirstSynAckPacket().ToBytes()
						So(err, ShouldBeNil)

						tcpPacket, err = packet.New(0, input, "0", true)
						if err == nil && tcpPacket != nil {
							tcpPacket.UpdateIPChecksum()
							tcpPacket.UpdateTCPChecksum()
						}
						err = enforcer.processApplicationTCPPackets(tcpPacket)
						So(err, ShouldBeNil)

						output = make([]byte, len(tcpPacket.GetBytes()))
						copy(output, tcpPacket.GetBytes())

						outPacket, err = packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

						input, err = PacketFlow.GetFirstAckPacket().ToBytes()
						So(err, ShouldBeNil)

						tcpPacket, err = packet.New(0, input, "0", true)
						if err == nil && tcpPacket != nil {
							tcpPacket.UpdateIPChecksum()
							tcpPacket.UpdateTCPChecksum()
						}
						err = enforcer.processApplicationTCPPackets(tcpPacket)
						CheckAfterAppAckPacket(enforcer, tcpPacket)
						So(err, ShouldBeNil)

						output = make([]byte, len(tcpPacket.GetBytes()))
						copy(output, tcpPacket.GetBytes())

						outPacket, err = packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						CheckBeforeNetAckPacket(enforcer, tcpPacket, outPacket, false)
						err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

					})

				} else if k == 1 {

					puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, false, "server", false)
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

						err = enforcer.processApplicationTCPPackets(tcpPacket)
						//After sending syn packet
						CheckAfterAppSynPacket(enforcer, tcpPacket)
						So(err, ShouldBeNil)
						output := make([]byte, len(tcpPacket.GetBytes()))
						copy(output, tcpPacket.GetBytes())

						outPacket, err := packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						err = enforcer.processNetworkTCPPackets(outPacket)
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
						err = enforcer.processApplicationTCPPackets(tcpPacket)
						So(err, ShouldBeNil)

						output := make([]byte, len(tcpPacket.GetBytes()))
						copy(output, tcpPacket.GetBytes())

						outPacket, err := packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						outPacket.Print(0)
						err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

						//Now lets send the synack packet from the server in response
						input, err = PacketFlow.GetFirstSynAckPacket().ToBytes()
						So(err, ShouldBeNil)

						tcpPacket, err = packet.New(0, input, "0", true)
						if err == nil && tcpPacket != nil {
							tcpPacket.UpdateIPChecksum()
							tcpPacket.UpdateTCPChecksum()
						}
						err = enforcer.processApplicationTCPPackets(tcpPacket)
						So(err, ShouldBeNil)

						output = make([]byte, len(tcpPacket.GetBytes()))
						copy(output, tcpPacket.GetBytes())

						outPacket, err = packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						outPacketcopy, _ := packet.New(0, output, "0", true)
						err = enforcer.processNetworkTCPPackets(outPacket)
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
						err = enforcer.processApplicationTCPPackets(tcpPacket)
						So(err, ShouldBeNil)

						output := make([]byte, len(tcpPacket.GetBytes()))
						copy(output, tcpPacket.GetBytes())

						outPacket, err := packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

						//Now lets send the synack packet from the server in response
						input, err = PacketFlow.GetFirstSynAckPacket().ToBytes()
						So(err, ShouldBeNil)

						tcpPacket, err = packet.New(0, input, "0", true)
						if err == nil && tcpPacket != nil {
							tcpPacket.UpdateIPChecksum()
							tcpPacket.UpdateTCPChecksum()
						}
						err = enforcer.processApplicationTCPPackets(tcpPacket)
						So(err, ShouldBeNil)

						output = make([]byte, len(tcpPacket.GetBytes()))
						copy(output, tcpPacket.GetBytes())

						outPacket, err = packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						err = enforcer.processNetworkTCPPackets(outPacket)
						So(err, ShouldBeNil)

						input, err = PacketFlow.GetFirstAckPacket().ToBytes()
						So(err, ShouldBeNil)

						tcpPacket, err = packet.New(0, input, "0", true)
						if err == nil && tcpPacket != nil {
							tcpPacket.UpdateIPChecksum()
							tcpPacket.UpdateTCPChecksum()
						}
						err = enforcer.processApplicationTCPPackets(tcpPacket)
						CheckAfterAppAckPacket(enforcer, tcpPacket)
						So(err, ShouldBeNil)

						output = make([]byte, len(tcpPacket.GetBytes()))
						copy(output, tcpPacket.GetBytes())

						outPacket, err = packet.New(0, output, "0", true)
						So(err, ShouldBeNil)
						CheckBeforeNetAckPacket(enforcer, tcpPacket, outPacket, false)
						err = enforcer.processNetworkTCPPackets(outPacket)
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

			puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, false, "server", false)
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
					}

					output := make([]byte, len(tcpPacket.GetBytes()))
					copy(output, tcpPacket.GetBytes())

					outPacket, errp := packet.New(0, output, "0", true)
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
	Convey("Given I create a new enforcer instance", t, func() {
		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
		collector := &collector.DefaultCollector{}
		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}
		enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.LocalServer, "/proc", []string{"0.0.0.0/0"})
		contextID := "123"

		puInfo := policy.NewPUInfo(contextID, common.ContainerPU)

		// Should fail: Not in cache
		err := enforcer.Unenforce(contextID)
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
		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
		collector := &collector.DefaultCollector{}

		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.LocalServer, "/proc", []string{"0.0.0.0/0"})
		enforcer.mode = constants.LocalServer
		contextID := "123"
		puInfo := policy.NewPUInfo(contextID, common.LinuxProcessPU)

		spec, _ := portspec.NewPortSpecFromString("80", nil)
		puInfo.Runtime.SetOptions(policy.OptionsType{
			CgroupMark: "100",
			Services: []common.Service{
				common.Service{
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
		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
		collector := &collector.DefaultCollector{}
		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.LocalServer, "/proc", []string{"0.0.0.0/0"})
		enforcer.mode = constants.LocalServer
		contextID := "123"
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
		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
		collector := &collector.DefaultCollector{}

		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.LocalServer, "/proc", []string{"0.0.0.0/0"})
		enforcer.mode = constants.RemoteContainer

		contextID := "123"
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
		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
		collector := &collector.DefaultCollector{}

		// mock the call
		prevRawSocket := GetUDPRawSocket
		defer func() {
			GetUDPRawSocket = prevRawSocket
		}()
		GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
			return nil, nil
		}

		enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.RemoteContainer, "/proc", []string{"0.0.0.0/0"})

		puInfo := policy.NewPUInfo("SomePU", common.ContainerPU)

		context, err := pucontext.NewPU("SomePU", puInfo, 10*time.Second)
		contextID := "AporetoContext"
		So(err, ShouldBeNil)

		Convey("If I try to get context based on IP and its  not there and its a local container it should fail ", func() {
			_, err := enforcer.contextFromIP(true, "20.1.1.1", "", 0, packet.IPProtocolTCP)
			So(err, ShouldNotBeNil)
		})

		Convey("If there is no IP match, it should try the mark for app packets ", func() {
			enforcer.puFromMark.AddOrUpdate("100", context)
			enforcer.mode = constants.LocalServer

			Convey("If the mark exists", func() {
				ctx, err := enforcer.contextFromIP(true, "20.1.1.1", "100", 0, packet.IPProtocolTCP)
				So(err, ShouldBeNil)
				So(ctx, ShouldNotBeNil)
				So(ctx, ShouldEqual, context)
			})

			Convey("If the mark doesn't exist", func() {
				_, err := enforcer.contextFromIP(true, "20.1.1.1", "2000", 0, packet.IPProtocolTCP)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("If there is no IP match, it should try the port for net packets ", func() {
			s, _ := portspec.NewPortSpec(8000, 8000, contextID)
			enforcer.contextIDFromTCPPort.AddPortSpec(s)
			enforcer.puFromContextID.AddOrUpdate(contextID, context)
			enforcer.mode = constants.LocalServer

			Convey("If the port exists", func() {
				ctx, err := enforcer.contextFromIP(false, "20.1.1.1", "", 8000, packet.IPProtocolTCP)
				So(err, ShouldBeNil)
				So(ctx, ShouldNotBeNil)
				So(ctx, ShouldEqual, context)
			})

			Convey("If the port doesn't exist", func() {
				_, err := enforcer.contextFromIP(false, "20.1.1.1", "", 9000, packet.IPProtocolTCP)
				So(err, ShouldNotBeNil)
			})
		})

	})
}

func TestInvalidPacket(t *testing.T) {
	// collector := &collector.DefaultCollector{}
	// secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
	// enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.RemoteContainer, "/proc")
	var puInfo1, puInfo2 *policy.PUInfo
	var enforcer *Datapath
	var err1, err2 error

	Convey("When I receive an invalid packet", t, func() {

		for k := 0; k < 2; k++ {
			if k == 0 {

				puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, false, "container", false)
				So(puInfo1, ShouldNotBeNil)
				So(puInfo2, ShouldNotBeNil)
				So(err1, ShouldBeNil)
				So(err2, ShouldBeNil)

			} else if k == 1 {

				puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, false, "server", false)
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
				err = enforcer.processApplicationTCPPackets(tcpPacket)
				So(err, ShouldBeNil)
				output := make([]byte, len(tcpPacket.GetBytes()))
				copy(output, tcpPacket.GetBytes())
				outpacket, err := packet.New(0, output, "0", true)
				So(err, ShouldBeNil)
				//Detach the data and parse token should fail
				err = outpacket.TCPDataDetach(binary.BigEndian.Uint16([]byte{0x0, p[32]})/4 - 20)
				So(err, ShouldBeNil)
				err = enforcer.processNetworkTCPPackets(outpacket)
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

			puInfo1, puInfo2, enforcer, err1, err2, _, _ := setupProcessingUnitsInDatapathAndEnforce(nil, false, "container", false)

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

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "server", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						}
						PacketFlow := packetgen.NewPacketFlow("aa:ff:aa:ff:aa:ff", "ff:aa:ff:aa:ff:aa", "10.1.10.76", "164.67.228.152", 666, 80)
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

							outPacket, errp := packet.New(0, output, "0", true)
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

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(0)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(0)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "server", false)
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
								SIP = tcpPacket.SourceAddress
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
								t.Error("Invalid Test Packet")
							}

							err = enforcer.processApplicationTCPPackets(tcpPacket)
							CheckAfterAppSynPacket(enforcer, tcpPacket)
							So(err, ShouldBeNil)

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetBytes()))
							copy(output, tcpPacket.GetBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
							So(errp, ShouldBeNil)
							err = enforcer.processNetworkTCPPackets(outPacket)
							CheckAfterNetSynPacket(enforcer, tcpPacket, outPacket)
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

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(0)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(0)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "server", false)
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

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
							So(errp, ShouldBeNil)

							outPacketcopy, _ := packet.New(0, output, "0", true)
							err = enforcer.processNetworkTCPPackets(outPacket)
							So(err, ShouldBeNil)

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								CheckAfterNetSynAckPacket(t, enforcer, outPacketcopy, outPacket)
							}

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

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "server", false)
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
								SIP = tcpPacket.SourceAddress
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
								t.Error("Invalid Test Packet")
							}

							err = enforcer.processApplicationTCPPackets(tcpPacket)
							So(err, ShouldBeNil)
							if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								CheckAfterAppAckPacket(enforcer, tcpPacket)
							}

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetBytes()))
							copy(output, tcpPacket.GetBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
							So(errp, ShouldBeNil)
							if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								CheckBeforeNetAckPacket(enforcer, tcpPacket, outPacket, false)
							}
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

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "server", false)
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

							outPacket, errp := packet.New(0, output, "0", true)
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
					}
					Convey("Then I expect all the input and output packets (after encoding and decoding) to be same", func() {

						So(packetDiffers, ShouldEqual, false)
					})
				})
			})
		})
	})
}

//
// func TestFlowReportingMultipleFlows(t *testing.T) {
//
// 	ctrl := gomock.NewController(t)
// 	defer ctrl.Finish()
//
// 	mockCollector := mockcollector.NewMockEventCollector(ctrl)
//
// 	SIP := net.IPv4zero
// 	packetDiffers := false
//
// 	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {
//
// 		Convey("Given I create a two processing unit instances", func() {
// 			var puInfo1, puInfo2 *policy.PUInfo
// 			var enforcer *Datapath
// 			var err1, err2 error
//
// 			Convey("When I pass multiple different flows (2 in this case) through the enforcer", func() {
//
// 				Convey("Then I expect the flows to be reported twice", func() {
// 					for k := 0; k < 2; k++ {
// 						if k == 0 {
//
// 							mockCollector.EXPECT().CollectFlowEvent(gomock.Any()).Times(2)
//
// 							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, true, "container")
// 							So(puInfo1, ShouldNotBeNil)
// 							So(puInfo2, ShouldNotBeNil)
// 							So(err1, ShouldBeNil)
// 							So(err2, ShouldBeNil)
//
// 						} else if k == 1 {
//
// 							mockCollector.EXPECT().CollectFlowEvent(gomock.Any()).Times(2)
//
// 							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, true, "server")
// 							So(puInfo1, ShouldNotBeNil)
// 							So(puInfo2, ShouldNotBeNil)
// 							So(err1, ShouldBeNil)
// 							So(err2, ShouldBeNil)
//
// 						}
// 						PacketFlow := packetgen.NewTemplateFlow()
// 						PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeMultipleIntervenedFlow)
//
// 						for i := 0; i < PacketFlow.GetNumPackets(); i++ {
//
// 							oldPacket, err := packet.New(0, PacketFlow.GetNthPacket(i).ToBytes(), "0")
// 							if err == nil && oldPacket != nil {
// 								oldPacket.UpdateIPChecksum()
// 								oldPacket.UpdateTCPChecksum()
// 							}
// 							tcpPacket, err := packet.New(0, PacketFlow.GetNthPacket(i).ToBytes(), "0")
// 							if err == nil && tcpPacket != nil {
// 								tcpPacket.UpdateIPChecksum()
// 								tcpPacket.UpdateTCPChecksum()
// 							}
//
// 							if debug {
// 								fmt.Println("Input packet", i)
// 								tcpPacket.Print(0)
// 							}
//
// 							So(err, ShouldBeNil)
// 							So(tcpPacket, ShouldNotBeNil)
//
// 							if reflect.DeepEqual(SIP, net.IPv4zero) {
// 								SIP = tcpPacket.SourceAddress
// 							}
// 							fmt.Println(PacketFlow.GetNthPacket(i).GetIPPacket())
// 							err = enforcer.processApplicationTCPPackets(tcpPacket)
// 							So(err, ShouldBeNil)
//
// 							if debug {
// 								fmt.Println("Intermediate packet", i)
// 								tcpPacket.Print(0)
// 							}
//
// 							output := make([]byte, len(tcpPacket.GetBytes()))
// 							copy(output, tcpPacket.GetBytes())
//
// 							outPacket, errp := packet.New(0, output, "0", true)
// 							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
// 							So(errp, ShouldBeNil)
// 							err = enforcer.processNetworkTCPPackets(outPacket)
//
// 							So(err, ShouldBeNil)
//
// 							if debug {
// 								fmt.Println("Output packet", i)
// 								outPacket.Print(0)
// 							}
//
// 							if !reflect.DeepEqual(oldPacket.GetBytes(), outPacket.GetBytes()) {
// 								packetDiffers = true
// 								fmt.Println("Error: packets dont match")
// 								fmt.Println("Input Packet")
// 								oldPacket.Print(0)
// 								fmt.Println("Output Packet")
// 								outPacket.Print(0)
// 								t.Errorf("Packet %d Input and output packet do not match", i)
// 								t.FailNow()
// 							}
// 						}
// 					}
// 					Convey("Then I expect all the input and output packets (after encoding and decoding) to be same", func() {
//
// 						So(packetDiffers, ShouldEqual, false)
// 					})
// 				})
// 			})
// 		})
// 	})
// }

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

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "server", false)
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
								SIP = tcpPacket.SourceAddress
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
								t.Error("Invalid Test Packet")
							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() && isSynPacket {
								fmt.Println("This a app (A)", i)
								err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							} else if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && isSynAckPacket {
								fmt.Println("This a app (B)", i)
								err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							} else if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								fmt.Println("This a app (C)", i)
								err = enforcer.processApplicationTCPPackets(tcpPacket)
								isSynAckPacket = true
								So(err, ShouldBeNil)
							} else {
								fmt.Println("This a app (D)", i)
								err = enforcer.processApplicationTCPPackets(tcpPacket)
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

							output := make([]byte, len(tcpPacket.GetBytes()))
							copy(output, tcpPacket.GetBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
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
								err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							} else if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && isSynAckNetPacket {
								fmt.Println("This a net (B)", i)
								err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							} else if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								fmt.Println("This a net (C)", i)
								err = enforcer.processNetworkTCPPackets(outPacket)
								isSynAckNetPacket = true
								So(err, ShouldBeNil)
							} else {
								fmt.Println("This is net (C)", i)
								err = enforcer.processNetworkTCPPackets(outPacket)
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

			puInfo1, puInfo2, enforcer, err1, err2, _, _ := setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "container", false)

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

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "server", false)
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
								SIP = tcpPacket.SourceAddress
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
								t.Error("Invalid Test Packet")
							}

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() && isSynReceived {
								fmt.Println("This is App (A)", i)
								isSynAckReceived = true
								err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							} else if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && isSynAckReceived {
								fmt.Println("This is App (B)", i)
								isSynAckReceived = true
								err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							} else {
								fmt.Println("This is App (C)", i)
								err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							}
							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetBytes()))
							copy(output, tcpPacket.GetBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
							So(errp, ShouldBeNil)

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() && isSynAckReceived {
								err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							} else if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && isSynAckReceived {
								err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							} else {
								fmt.Println("This is net (c)", i)
								isSynReceived = true
								err = enforcer.processNetworkTCPPackets(outPacket)
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

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, false, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(nil, false, "server", false)
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
								SIP = tcpPacket.SourceAddress
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
								t.Error("Invalid Test Packet")
							}

							enforcer.processApplicationTCPPackets(tcpPacket) // nolint: errcheck

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetBytes()))
							copy(output, tcpPacket.GetBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
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

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "server", false)
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
								SIP = tcpPacket.SourceAddress
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
								t.Error("Invalid Test Packet")
							}

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetBytes()))
							copy(output, tcpPacket.GetBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
							So(errp, ShouldBeNil)
							err = enforcer.processNetworkTCPPackets(outPacket)
							So(err, ShouldNotBeNil)

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

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							mockCollector.EXPECT().CollectFlowEvent(gomock.Any()).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "server", false)
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
								SIP = tcpPacket.SourceAddress
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
								t.Error("Invalid Test Packet")
							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() {
								err = enforcer.processApplicationTCPPackets(tcpPacket)

								So(err, ShouldBeNil)
							}

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetBytes()))
							copy(output, tcpPacket.GetBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
							So(errp, ShouldBeNil)

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() {
								err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldNotBeNil)
							}

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

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "server", false)
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
								SIP = tcpPacket.SourceAddress
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
								t.Error("Invalid Test Packet")
							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() {

								err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)

							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {

								err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)

							}

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetBytes()))
							copy(output, tcpPacket.GetBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
							So(errp, ShouldBeNil)

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() {

								err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)

							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {

								err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)

							}
							if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && !PacketFlow.GetNthPacket(i).GetTCPFin() {

								err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldNotBeNil)

							}

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

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "server", false)
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
								SIP = tcpPacket.SourceAddress
							}

							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
								t.Error("Invalid Test Packet")
							}

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {

								err = enforcer.processApplicationTCPPackets(tcpPacket)
								// The app synack packet will be considered as non PU traffic
								So(err, ShouldBeNil)
							}

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								s, _ := portspec.NewPortSpec(80, 80, "123456")
								enforcer.contextIDFromTCPPort.AddPortSpec(s)

								err = enforcer.processApplicationTCPPackets(tcpPacket)
								// The app synack packet will be considered as non PU traffic
								So(err, ShouldNotBeNil)
							}

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetBytes()))
							copy(output, tcpPacket.GetBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
							So(errp, ShouldBeNil)

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() {

								err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldNotBeNil)

							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)

							}

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

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "server", false)
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
								SIP = tcpPacket.SourceAddress
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
								t.Error("Invalid Test Packet")
							}

							if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && !PacketFlow.GetNthPacket(i).GetTCPFin() {

								err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							}

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetBytes()))
							copy(output, tcpPacket.GetBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
							So(errp, ShouldBeNil)

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() {

								err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldNotBeNil)

							}
							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
								err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)

							}
							if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && !PacketFlow.GetNthPacket(i).GetTCPFin() {

								err = enforcer.processNetworkTCPPackets(outPacket)
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

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "server", false)
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
								SIP = tcpPacket.SourceAddress
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
								t.Error("Invalid Test Packet")
							}

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() && isAckPacket {
								fmt.Println("This is App (A)", i)
								err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							} else {
								fmt.Println("This is App (B)", i)
								err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							}

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetBytes()))
							copy(output, tcpPacket.GetBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
							So(errp, ShouldBeNil)

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() && isAckPacket {
								fmt.Println("This is network (A)", i)
								err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							} else if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && isAckPacket {
								fmt.Println("This is network (B)", i)
								err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							} else {
								fmt.Println("This is network (C)", i)
								err = enforcer.processNetworkTCPPackets(outPacket)
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

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Accept

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "server", false)
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
								SIP = tcpPacket.SourceAddress
							}
							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) &&
								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
								t.Error("Invalid Test Packet")
							}

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() && isAckPacket {
								fmt.Println("This is App (A)", i)
								err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							} else if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && isAckPacket {
								fmt.Println("This is App (B)", i)
								err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							} else {
								fmt.Println("This is App (C)", i)
								err = enforcer.processApplicationTCPPackets(tcpPacket)
								So(err, ShouldBeNil)
							}

							if debug {
								fmt.Println("Intermediate packet", i)
								tcpPacket.Print(0)
							}

							output := make([]byte, len(tcpPacket.GetBytes()))
							copy(output, tcpPacket.GetBytes())

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
							So(errp, ShouldBeNil)

							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() && isAckPacket {
								fmt.Println("This is network (A)", i)
								err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
								fmt.Println(err)
							} else if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && isAckPacket {
								fmt.Println("This is network (B)", i)
								err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldBeNil)
							} else {
								fmt.Println("This is network (C)", i)
								err = enforcer.processNetworkTCPPackets(outPacket)
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

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {
							var flowRecord collector.FlowRecord
							var srcEndPoint collector.EndPoint
							var dstEndPoint collector.EndPoint

							srcEndPoint.IP = "10.1.10.76"
							dstEndPoint.IP = "164.67.228.152"
							dstEndPoint.Port = 80

							flowRecord.Count = 1
							flowRecord.Source = &srcEndPoint
							flowRecord.Destination = &dstEndPoint
							flowRecord.Action = policy.Reject

							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "server", false)
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

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
							So(errp, ShouldBeNil)

							//changing the option length
							outPacket.Buffer[outPacket.TCPDataStartBytes()-enforcerconstants.TCPAuthenticationOptionBaseLen] = 233

							err = enforcer.processNetworkTCPPackets(outPacket)
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

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "container", false)
							So(puInfo1, ShouldNotBeNil)
							So(puInfo2, ShouldNotBeNil)
							So(err1, ShouldBeNil)
							So(err2, ShouldBeNil)

						} else if k == 1 {

							mockCollector.EXPECT().CollectFlowEvent(gomock.Any()).Times(1)

							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "server", false)
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

							outPacket, errp := packet.New(0, output, "0", true)
							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
							So(errp, ShouldBeNil)

							if PacketFlow.GetUptoFirstSynAckPacket().GetNthPacket(i).GetTCPSyn() && PacketFlow.GetUptoFirstSynAckPacket().GetNthPacket(i).GetTCPAck() {
								//changing the option length of SynAck packet
								outPacket.Buffer[outPacket.TCPDataStartBytes()-enforcerconstants.TCPAuthenticationOptionBaseLen] = 233
								err = enforcer.processNetworkTCPPackets(outPacket)
								So(err, ShouldNotBeNil)
							} else {
								err = enforcer.processNetworkTCPPackets(outPacket)
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
			serverID := "SomeServerId"

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

			secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))

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

				outPacket, errp := packet.New(0, output, "0", true)
				So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
				So(errp, ShouldBeNil)

				err = enforcer.processNetworkTCPPackets(outPacket)
				So(err, ShouldNotBeNil)

				if debug {
					fmt.Println("Output packet", i)
					outPacket.Print(0)
				}
			}
		})
	})
}

// func TestReportingDelayInNetwork(t *testing.T) {

// 	ctrl := gomock.NewController(t)
// 	defer ctrl.Finish()

// 	mockCollector := mockcollector.NewMockEventCollector(ctrl)

// 	SIP := net.IPv4zero
// 	//packetDiffers := false

// 	Convey("Given I create a new enforcer instance and have a valid processing unit context", t, func() {

// 		Convey("Given I create a two processing unit instances", func() {

// 			puInfo1, puInfo2, enforcer, err1, err2, _, _ := setupProcessingUnitsInDatapathAndEnforce(nil, false, "container")

// 			So(puInfo1, ShouldNotBeNil)
// 			So(puInfo2, ShouldNotBeNil)
// 			So(err1, ShouldBeNil)
// 			So(err2, ShouldBeNil)

// 			Convey("When I pass multiple packets with delay of Syn and SynAck packets", func() {

// 				Convey("Then I expect the flow to be reported only once with states intact", func() {
// 					for k := 0; k < 2; k++ {
// 						if k == 0 {

// 							var flowRecord collector.FlowRecord

// 							flowRecord.Count = 1
// 							flowRecord.Source.IP = "10.1.10.76"
// 							flowRecord.Destination.IP = "164.67.228.152"
// 							flowRecord.Destination.Port = 80
// 							flowRecord.Action = policy.Reject

// 							fmt.Println("This is a Container")
// 							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

// 							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "container")
// 							So(puInfo1, ShouldNotBeNil)
// 							So(puInfo2, ShouldNotBeNil)
// 							So(err1, ShouldBeNil)
// 							So(err2, ShouldBeNil)

// 						} else if k == 1 {

// 							var flowRecord collector.FlowRecord

// 							flowRecord.Count = 1
// 							flowRecord.Source.IP = "10.1.10.76"
// 							flowRecord.Destination.IP = "164.67.228.152"
// 							flowRecord.Destination.Port = 80
// 							flowRecord.Action = policy.Reject

// 							fmt.Println("This is a Server")
// 							mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

// 							puInfo1, puInfo2, enforcer, err1, err2, _, _ = setupProcessingUnitsInDatapathAndEnforce(mockCollector, false, "server")
// 							So(puInfo1, ShouldNotBeNil)
// 							So(puInfo2, ShouldNotBeNil)
// 							So(err1, ShouldBeNil)
// 							So(err2, ShouldBeNil)

// 						}
// 						PacketFlow := packetgen.NewTemplateFlow()
// 						PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)

// 						var isAckPacket, isSynAckPacket, isDone bool
// 						//		var checkAfterAppAckFlag, checkBeforeNetAckFlag bool
// 						var connSynAck [][]byte

// 						for i := 0; i < 4; i++ {
// 							if isDone {
// 								break
// 							}
// 							if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && !isAckPacket {
// 								i = 0
// 								isAckPacket = true
// 							} else if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && !isSynAckPacket && isAckPacket {
// 								i = 2
// 								isSynAckPacket = true
// 							}

// 							oldPacket, err := packet.New(0, PacketFlow.GetNthPacket(i).ToBytes(), "0")
// 							if err == nil && oldPacket != nil {
// 								oldPacket.UpdateIPChecksum()
// 								oldPacket.UpdateTCPChecksum()
// 							}
// 							tcpPacket, err := packet.New(0, PacketFlow.GetNthPacket(i).ToBytes(), "0")
// 							if err == nil && tcpPacket != nil {
// 								tcpPacket.UpdateIPChecksum()
// 								tcpPacket.UpdateTCPChecksum()

// 							}
// 							if debug {
// 								fmt.Println("Input packet", i)
// 								tcpPacket.Print(0)
// 							}

// 							So(err, ShouldBeNil)
// 							So(tcpPacket, ShouldNotBeNil)

// 							if reflect.DeepEqual(SIP, net.IPv4zero) {
// 								SIP = tcpPacket.SourceAddress
// 							}
// 							if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress) &&
// 								!reflect.DeepEqual(SIP, tcpPacket.SourceAddress) {
// 								t.Error("Invalid Test Packet")
// 							}
// 							fmt.Println("This is all App packet", i)
// 							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() && isAckPacket && isSynAckPacket {
// 								fmt.Println("This is App packet (A)", i)
// 								err = enforcer.processApplicationTCPPackets(tcpPacket)

// 								// if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() {
// 								// 	CheckAfterAppSynPacket(enforcer, tcpPacket)
// 								// }
// 								//
// 								// if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && !checkAfterAppAckFlag {
// 								// 	CheckAfterAppAckPacket(enforcer, tcpPacket)
// 								// 	checkAfterAppAckFlag = true
// 								//
// 								// }
// 								So(err, ShouldNotBeNil)
// 							} else {
// 								fmt.Println("This is App packet (B)", i)
// 								err = enforcer.processApplicationTCPPackets(tcpPacket)

// 								So(err, ShouldBeNil)
// 							}

// 							if debug {
// 								fmt.Println("Intermediate packet", i)
// 								tcpPacket.Print(0)
// 							}

// 							output := make([]byte, len(tcpPacket.GetBytes()))
// 							copy(output, tcpPacket.GetBytes())

// 							outPacket, errp := packet.New(0, output, "0", true)
// 							So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
// 							So(errp, ShouldBeNil)

// 							if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
// 								netconn, _ := enforcer.sourcePortConnectionCache.Get(outPacket.SourcePortHash(packet.PacketTypeNetwork))
// 								connSynAck = append(connSynAck, netconn.(*connection.TCPConnection).Auth.LocalContext)
// 							}
// 							//
// 							// if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && !PacketFlow.GetNthPacket(i).GetTCPFin() && !checkBeforeNetAckFlag {
// 							// 	CheckBeforeNetAckPacket(enforcer, tcpPacket, outPacket, checkBeforeNetAckFlag)
// 							// 	checkBeforeNetAckFlag = true
// 							// }
// 							if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() && isAckPacket {
// 								i = 2
// 								fmt.Println("This is Network packet (A)", i)
// 								tcpPacket, err = packet.New(0, PacketFlow.GetNthPacket(i).ToBytes(), "0")
// 								if err == nil && tcpPacket != nil {
// 									tcpPacket.UpdateIPChecksum()
// 									tcpPacket.UpdateTCPChecksum()
// 								}
// 								enforcer.processApplicationTCPPackets(tcpPacket)
// 								output := make([]byte, len(tcpPacket.GetBytes()))
// 								copy(output, tcpPacket.GetBytes())

// 								outPacket, errp = packet.New(0, output, "0", true)
// 								So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
// 								So(errp, ShouldBeNil)

// 								err = enforcer.processNetworkTCPPackets(outPacket)

// 								So(err, ShouldNotBeNil)
// 							} else if !PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() && isSynAckPacket && isAckPacket && !isDone {
// 								i = 0

// 								fmt.Println("This is Network packet (B)", i)
// 								tcpPacket, err = packet.New(0, PacketFlow.GetNthPacket(i).ToBytes(), "0")
// 								if err == nil && tcpPacket != nil {
// 									tcpPacket.UpdateIPChecksum()
// 									tcpPacket.UpdateTCPChecksum()
// 								}
// 								err = enforcer.processApplicationTCPPackets(tcpPacket)

// 								So(err, ShouldBeNil)
// 								output := make([]byte, len(tcpPacket.GetBytes()))
// 								copy(output, tcpPacket.GetBytes())

// 								outPacket, errp = packet.New(0, output, "0", true)
// 								So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
// 								So(errp, ShouldBeNil)

// 								err = enforcer.processNetworkTCPPackets(outPacket)

// 								So(err, ShouldBeNil)
// 								isDone = true
// 							} else {
// 								fmt.Println("This is Network packet (C)", i)
// 								err = enforcer.processNetworkTCPPackets(outPacket)

// 								So(err, ShouldBeNil)
// 							}
// 							if debug {
// 								fmt.Println("Output packet", i)
// 								outPacket.Print(0)
// 							}

// 							// if !reflect.DeepEqual(oldPacket.GetBytes(), outPacket.GetBytes()) {
// 							// 	packetDiffers = true
// 							// 	fmt.Println("Error: packets dont match")
// 							// 	fmt.Println("Input Packet")
// 							// 	oldPacket.Print(0)
// 							// 	fmt.Println("Output Packet")
// 							// 	outPacket.Print(0)
// 							// 	t.Errorf("Packet %d Input and output packet do not match", i)
// 							// 	t.FailNow()
// 							// }

// 						}
// 						for j := 0; j < len(connSynAck)-1; j++ {
// 							for k := 0; k < len(connSynAck[j]); k++ {
// 								//So(connSynAck[j][k], ShouldEqual, connSynAck[j+1][k])
// 							}
// 						}
// 					}
// 				})
// 			})
// 		})
// 	})
// }

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
						PacketFlow := packetgen.NewPacketFlow("aa:ff:aa:ff:aa:ff", "ff:aa:ff:aa:ff:aa", "10.1.10.76", "164.67.228.152", 666, 80)
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGenerateGoodFlow)
						So(err, ShouldBeNil)
						iteration = iteration + 1
						puID1 := "SomeProcessingUnitId" + string(iteration) + "1"
						puID2 := "SomeProcessingUnitId" + string(iteration) + "2"
						puIP1 := "164.67.228.152" // + strconv.Itoa(iteration)
						puIP2 := "10.1.10.76"     // + strconv.Itoa(iteration)
						serverID := "SomeServerId"

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

						secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
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
						PacketFlow := packetgen.NewPacketFlow("aa:ff:aa:ff:aa:ff", "ff:aa:ff:aa:ff:aa", "10.1.10.76", "164.67.228.152", 666, 80)
						_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGenerateGoodFlow)
						So(err, ShouldBeNil)
						iteration = iteration + 1
						puID1 := "SomeProcessingUnitId" + string(iteration) + "1"
						puID2 := "SomeProcessingUnitId" + string(iteration) + "2"
						puIP1 := "164.67.228.152" // + strconv.Itoa(iteration)
						puIP2 := "10.1.10.76"     // + strconv.Itoa(iteration)
						serverID := "SomeServerId"

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

						secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
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
					PacketFlow := packetgen.NewPacketFlow("aa:ff:aa:ff:aa:ff", "ff:aa:ff:aa:ff:aa", "10.1.10.76", "164.67.228.152", 666, 80)
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

						outPacket, errp := packet.New(0, output, "0", true)
						So(len(tcpPacket.GetBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetBytes()))
						So(errp, ShouldBeNil)

						err = enforcer.processNetworkTCPPackets(outPacket)
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
		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
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
				return []string{"164.67.228.152"}, nil
			}

			return nil, fmt.Errorf("Error")
		}

		puID1 := "SomePU"
		enforcer := NewWithDefaults("SomeServerId", collector, nil, secret, constants.RemoteContainer, "/proc", []string{"1.1.1.1/31"})
		puInfo := policy.NewPUInfo(puID1, common.ContainerPU)
		puInfo.Policy.UpdateDNSNetworks([]policy.DNSRule{{
			Name:     externalFQDN,
			Port:     "80",
			Protocol: "tcp",
			Policy:   &policy.FlowPolicy{Action: policy.Accept},
		}})

		err2 = enforcer.Enforce(puID1, puInfo)
		time.Sleep(5 * time.Second)
		defer lock.Unlock()
		lock.Lock()
		So(err1, ShouldBeNil)
		So(err2, ShouldBeNil)

		PacketFlow := packetgen.NewPacketFlow("aa:ff:aa:ff:aa:ff", "ff:aa:ff:aa:ff:aa", "10.1.10.76", "10.0.0.0", 666, 80)
		_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
		So(err, ShouldBeNil)

		synPacket, err := PacketFlow.GetFirstSynPacket().ToBytes()
		So(err, ShouldBeNil)

		tcpPacket, err := packet.New(0, synPacket, "0", true)
		if err == nil && tcpPacket != nil {
			tcpPacket.UpdateIPChecksum()
			tcpPacket.UpdateTCPChecksum()
		}
		err1 := enforcer.processApplicationTCPPackets(tcpPacket)
		So(err1, ShouldBeNil)
	})
}

func TestPUPortCreation(t *testing.T) {
	Convey("Given an initialized enforcer for Linux Processes", t, func() {
		secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))
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
