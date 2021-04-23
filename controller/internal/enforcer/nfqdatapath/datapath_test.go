// +build linux

package nfqdatapath

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	enforcerconstants "go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/packetgen"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/counters"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/flowtracking/mockflowclient"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packettracing"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/portspec"
	"gotest.tools/assert"
)

func TestEnforcerExternalNetworks(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testThePackets := func(enforcer *Datapath) {

		PacketFlow := packetgen.NewTemplateFlow()

		_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
		So(err, ShouldBeNil)

		synackPacket, err := PacketFlow.GetFirstSynAckPacket().ToBytes()
		So(err, ShouldBeNil)

		tcpPacket, _ := packet.New(0, synackPacket, "0", true)
		_, err1 := enforcer.processApplicationTCPPackets(tcpPacket)
		So(err1, ShouldBeNil)

	}

	Convey("When the mode is RemoteConainter", t, func() {

		enforcer, secrets, mockTokenAccessor, _, _ := NewWithMocks(ctrl, "serverID1", constants.RemoteContainer, []string{"0.0.0.0/0"}, true)

		secrets.EXPECT().TransmittedKey().Return([]byte("dummy")).AnyTimes()
		secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
		mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
		mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)

		iprules := policy.IPRuleList{policy.IPRule{
			Addresses: []string{"10.1.10.76/32"},
			Ports:     []string{"80"},
			Protocols: []string{constants.TCPProtoNum},
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "tcp172/8"},
		}}

		contextID := "123456"
		puInfo := policy.NewPUInfo(contextID, "/ns1", common.LinuxProcessPU)

		context, err := pucontext.NewPU(contextID, puInfo, mockTokenAccessor, 10*time.Second)
		So(err, ShouldBeNil)
		enforcer.puFromContextID.AddOrUpdate(contextID, context)
		s, _ := portspec.NewPortSpec(80, 80, contextID)
		enforcer.contextIDFromTCPPort.AddPortSpec(s)

		err = context.UpdateNetworkACLs(iprules)
		So(err, ShouldBeNil)

		testThePackets(enforcer)
	})
}

func TestInvalidContext(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	defer MockGetUDPRawSocket()()

	Convey("Given I create a new enforcer instance", t, func() {

		enforcer, _, _, _, _ := NewWithMocks(ctrl, "serverID", constants.LocalServer, []string{"0.0.0.0/0"}, true)

		PacketFlow := packetgen.NewTemplateFlow()
		_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
		So(err, ShouldBeNil)
		synPacket, err := PacketFlow.GetFirstSynPacket().ToBytes()
		So(err, ShouldBeNil)
		tcpPacket, err := packet.New(0, synPacket, "0", true)
		Convey("When I run a TCP Syn packet through a non existing context", func() {

			_, err1 := enforcer.processApplicationTCPPackets(tcpPacket)
			_, _, err2 := enforcer.processNetworkTCPPackets(tcpPacket)

			Convey("Then I should see an error for non existing context", func() {

				So(err, ShouldBeNil)
				So(err1, ShouldNotBeNil)
				So(err2, ShouldNotBeNil)
			})
		})
	})
}

func TestPacketHandlingFirstThreePacketsHavePayload(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testThePackets := func(enforcer *Datapath) {
		SIP := net.IPv4zero
		firstSynAckProcessed := false
		PacketFlow := packetgen.NewTemplateFlow()
		_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
		So(err, ShouldBeNil)
		for i := 0; i < PacketFlow.GetNumPackets(); i++ {
			oldPacketFromFlow, err := PacketFlow.GetNthPacket(i).ToBytes()
			So(err, ShouldBeNil)
			oldPacket, err := packet.New(0, oldPacketFromFlow, "0", true)
			if err == nil && oldPacket != nil {
				oldPacket.UpdateIPv4Checksum()
				oldPacket.UpdateTCPChecksum()
			}
			tcpPacketFromFlow, err := PacketFlow.GetNthPacket(i).ToBytes()
			So(err, ShouldBeNil)
			tcpPacket, err := packet.New(0, tcpPacketFromFlow, "0", true)
			if err == nil && tcpPacket != nil {
				tcpPacket.UpdateIPv4Checksum()
				tcpPacket.UpdateTCPChecksum()
			}
			if debug {
				fmt.Println("Input packet", i)
				tcpPacket.Print(0, false)
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
				tcpPacket.Print(0, false)
			}

			if tcpPacket.GetTCPFlags()&packet.TCPSynMask != 0 {
				Convey("When I pass a packet with SYN or SYN/ACK flags for packet "+strconv.Itoa(i), func() {
					Convey("Then I expect some data payload to exist on the packet "+strconv.Itoa(i), func() {
						// In our 3 way security handshake syn and syn-ack packet should grow in length
						So(tcpPacket.IPTotalLen(), ShouldBeGreaterThan, oldPacket.IPTotalLen())
					})
				})
			}

			if !firstSynAckProcessed && tcpPacket.GetTCPFlags()&packet.TCPSynAckMask == packet.TCPAckMask {
				firstSynAckProcessed = true
				Convey("When I pass the first packet with ACK flag for packet "+strconv.Itoa(i), func() {
					Convey("Then I expect some data payload to exist on the packet "+strconv.Itoa(i), func() {
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

			_, f, err := enforcer.processNetworkTCPPackets(outPacket)
			if f != nil {
				f()
			}

			So(err, ShouldBeNil)

			if debug {
				fmt.Println("Output packet", i)
				outPacket.Print(0, false)
			}
		}
	}

	flowRecord := CreateFlowRecord(1, testSrcIP, testDstIP, 666, 80, policy.Accept, "")

	Convey("When the mode is RemoteConainter", t, func() {

		enforcer, mockCollector := createEnforcerWithPolicy(ctrl, constants.RemoteContainer)
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)
		testThePackets(enforcer)

	})

	Convey("When the mode is LocalServer", t, func() {

		enforcer, mockCollector := createEnforcerWithPolicy(ctrl, constants.LocalServer)
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)
		testThePackets(enforcer)

	})
}

func TestInvalidIPContext(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	defer MockGetUDPRawSocket()()

	Convey("Given I create a new enforcer instance", t, func() {

		enforcer, secrets, mockTokenAccessor, mockCollector, mockDNS := NewWithMocks(ctrl, "serverID", constants.LocalServer, []string{"0.0.0.0/0"}, true)

		secrets.EXPECT().TransmittedKey().Return([]byte("dummy")).AnyTimes()
		secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
		mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
		mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)
		mockDNS.EXPECT().StartDNSServer(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
		mockDNS.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
		mockDNS.EXPECT().Unenforce(gomock.Any(), gomock.Any()).Times(1)
		mockDNS.EXPECT().SyncWithPlatformCache(gomock.Any(), gomock.Any()).Times(1)

		puInfo := policy.NewPUInfo("SomeProcessingUnitId", "/ns2", common.LinuxProcessPU)

		CounterReport := &collector.CounterReport{
			PUID:      puInfo.Policy.ManagementID(),
			Namespace: puInfo.Policy.ManagementNamespace(),
		}
		mockCollector.EXPECT().CollectCounterEvent(MyCounterMatcher(CounterReport)).MinTimes(1)

		enforcer.Enforce(context.Background(), "serverID", puInfo) // nolint
		defer func() {
			if err := enforcer.Unenforce(context.Background(), "serverID"); err != nil {
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

			_, err1 := enforcer.processApplicationTCPPackets(tcpPacket)
			_, _, err2 := enforcer.processNetworkTCPPackets(tcpPacket)

			Convey("Then I should see an error for missing IP", func() {

				So(err, ShouldBeNil)
				So(err1, ShouldNotBeNil)
				So(err2, ShouldNotBeNil)
			})
		})
	})
}

// TestEnforcerConnUnknownState test ensures that enforcer closes the
// connection by converting packets to rst when it finds connection
// to be in unknown state. This happens when enforcer has not seen the
// 3way handshake for a connection.
func TestEnforcerConnUnknownState(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testThePackets := func(enforcer *Datapath) {
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
				tcpPacket.UpdateIPv4Checksum()
				tcpPacket.UpdateTCPChecksum()
			}

			_, err1 := enforcer.processApplicationTCPPackets(tcpPacket)

			// Test whether the packet is modified with Fin/Ack
			if tcpPacket.GetTCPFlags() != 0x04 {
				t.Fail()
			}

			_, _, err2 := enforcer.processNetworkTCPPackets(&tcpPacketCopy)

			if tcpPacket.GetTCPFlags() != 0x04 {
				t.Fail()
			}

			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
		})
	}

	Convey("When the mode is RemoteConainter", t, func() {

		enforcer, _ := createEnforcerWithPolicy(ctrl, constants.RemoteContainer)
		testThePackets(enforcer)

	})

	Convey("When the mode is LocalServer", t, func() {

		enforcer, _ := createEnforcerWithPolicy(ctrl, constants.LocalServer)
		testThePackets(enforcer)

	})
}

func TestInvalidTokenContext(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	defer MockGetUDPRawSocket()()

	testThePackets := func(enforcer *Datapath) {

		PacketFlow := packetgen.NewTemplateFlow()
		_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
		So(err, ShouldBeNil)
		synPacket, err := PacketFlow.GetFirstSynPacket().ToBytes()
		So(err, ShouldBeNil)
		tcpPacket, err := packet.New(0, synPacket, "0", true)

		Convey("When I run a TCP Syn packet through an invalid existing context (missing IP)", func() {

			_, err1 := enforcer.processApplicationTCPPackets(tcpPacket)
			_, _, err2 := enforcer.processNetworkTCPPackets(tcpPacket)

			Convey("Then I should see an error for missing Token", func() {

				So(err, ShouldBeNil)
				So(err1, ShouldNotBeNil)
				So(err2, ShouldNotBeNil)
			})
		})
	}

	Convey("Given I create a new enforcer instance", t, func() {

		puInfo := policy.NewPUInfo("SomeProcessingUnitId", "/ns2", common.LinuxProcessPU)

		ip := policy.ExtendedMap{
			"brige": testDstIP,
		}
		puInfo.Runtime.SetIPAddresses(ip)

		enforcer, secrets, mockTokenAccessor, _, mockDNS := NewWithMocks(ctrl, "serverID", constants.LocalServer, []string{"0.0.0.0/0"}, true)

		secrets.EXPECT().TransmittedKey().Return([]byte("dummy")).AnyTimes()
		secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
		mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
		mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)
		mockDNS.EXPECT().StartDNSServer(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
		mockDNS.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
		mockDNS.EXPECT().SyncWithPlatformCache(gomock.Any(), gomock.Any()).Times(1)

		enforcer.Enforce(context.Background(), "serverID", puInfo) // nolint

		testThePackets(enforcer)
	})
}

func TestPacketHandlingDstPortCacheBehavior(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testThePackets := func(enforcer *Datapath) {

		SIP := net.IPv4zero

		Convey("When I pass multiple packets through the enforcer", func() {

			PacketFlow := packetgen.NewTemplateFlow()
			_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
			So(err, ShouldBeNil)
			for i := 0; i < PacketFlow.GetNumPackets(); i++ {
				oldPacketFromFlow, err := PacketFlow.GetNthPacket(i).ToBytes()
				So(err, ShouldBeNil)
				oldPacket, err := packet.New(0, oldPacketFromFlow, "0", true)
				if err == nil && oldPacket != nil {
					oldPacket.UpdateIPv4Checksum()
					oldPacket.UpdateTCPChecksum()
				}
				tcpPacketFromFlow, err := PacketFlow.GetNthPacket(i).ToBytes()
				So(err, ShouldBeNil)
				tcpPacket, err := packet.New(0, tcpPacketFromFlow, "0", true)
				if err == nil && tcpPacket != nil {
					tcpPacket.UpdateIPv4Checksum()
					tcpPacket.UpdateTCPChecksum()
				}

				if debug {
					fmt.Println("Input packet", i)
					tcpPacket.Print(0, false)
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
					tcpPacket.Print(0, false)
				}

				output := make([]byte, len(tcpPacket.GetTCPBytes()))
				copy(output, tcpPacket.GetTCPBytes())

				outPacket, errp := packet.New(0, output, "0", true)
				So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
				So(errp, ShouldBeNil)
				_, f, err := enforcer.processNetworkTCPPackets(outPacket)
				if f != nil {
					f()
				}

				So(err, ShouldBeNil)

				if debug {
					fmt.Println("Output packet", i)
					outPacket.Print(0, false)
				}
			}
		})
	}

	flowRecord := CreateFlowRecord(1, testSrcIP, testDstIP, 666, 80, policy.Accept, "")

	Convey("When the mode is RemoteConainter", t, func() {

		enforcer, mockCollector := createEnforcerWithPolicy(ctrl, constants.RemoteContainer)
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)
		testThePackets(enforcer)

	})

	Convey("When the mode is LocalServer", t, func() {

		enforcer, mockCollector := createEnforcerWithPolicy(ctrl, constants.LocalServer)
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)
		testThePackets(enforcer)

	})
}

func TestAckLost(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testThePackets := func(enforcer *Datapath) {
		PacketFlow := packetgen.NewTemplateFlow()
		_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
		So(err, ShouldBeNil)

		synPacket, err := PacketFlow.GetFirstSynPacket().ToBytes()
		So(err, ShouldBeNil)
		tcpPacket, err := packet.New(0, synPacket, "0", true)
		if err == nil && tcpPacket != nil {
			tcpPacket.UpdateIPv4Checksum()
			tcpPacket.UpdateTCPChecksum()
		}

		_, err = enforcer.processApplicationTCPPackets(tcpPacket)
		So(err, ShouldBeNil)

		output := make([]byte, len(tcpPacket.GetTCPBytes()))
		copy(output, tcpPacket.GetTCPBytes())

		outPacket, errp := packet.New(0, output, "0", true)
		So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
		So(errp, ShouldBeNil)

		_, f, err := enforcer.processNetworkTCPPackets(outPacket)
		if f != nil {
			f()
		}

		So(err, ShouldBeNil)

		input, _ := PacketFlow.GetFirstSynAckPacket().ToBytes()

		tcpPacket, _ = packet.New(0, input, "0", true)
		if tcpPacket != nil {
			tcpPacket.UpdateIPv4Checksum()
			tcpPacket.UpdateTCPChecksum()
		}

		_, err = enforcer.processApplicationTCPPackets(tcpPacket)
		So(err, ShouldBeNil)

		output = make([]byte, len(tcpPacket.GetTCPBytes()))
		copy(output, tcpPacket.GetTCPBytes())

		outPacket, _ = packet.New(0, output, "0", true)
		_, f, err = enforcer.processNetworkTCPPackets(outPacket)
		if f != nil {
			f()
		}
		So(err, ShouldBeNil)

		input, _ = PacketFlow.GetFirstAckPacket().ToBytes()
		tcpPacket, _ = packet.New(0, input, "0", true)
		if tcpPacket != nil {
			tcpPacket.UpdateIPv4Checksum()
			tcpPacket.UpdateTCPChecksum()
		}

		_, err = enforcer.processApplicationTCPPackets(tcpPacket)
		So(err, ShouldBeNil)
		//simulate drop, and re-transmit packets.

		input, _ = PacketFlow.GetFirstSynAckPacket().ToBytes()

		tcpPacket, _ = packet.New(0, input, "0", true)
		if tcpPacket != nil {
			tcpPacket.UpdateIPv4Checksum()
			tcpPacket.UpdateTCPChecksum()
		}

		_, err = enforcer.processApplicationTCPPackets(tcpPacket)
		assert.Equal(t, err, nil, "error should be nil")

		output = make([]byte, len(tcpPacket.GetTCPBytes()))
		copy(output, tcpPacket.GetTCPBytes())

		outPacket, _ = packet.New(0, output, "0", true)
		_, f, err = enforcer.processNetworkTCPPackets(outPacket)
		if f != nil {
			f()
		}
		assert.Equal(t, err, nil, "error should be nil")

		input, _ = PacketFlow.GetFirstAckPacket().ToBytes()

		tcpPacket, _ = packet.New(0, input, "0", true)
		if tcpPacket != nil {
			tcpPacket.UpdateIPv4Checksum()
			tcpPacket.UpdateTCPChecksum()
		}

		_, err = enforcer.processApplicationTCPPackets(tcpPacket)
		assert.Equal(t, err, nil, "error should be nil")

		output = make([]byte, len(tcpPacket.GetTCPBytes()))
		copy(output, tcpPacket.GetTCPBytes())

		outPacket, _ = packet.New(0, output, "0", true)

		_, f, err = enforcer.processNetworkTCPPackets(outPacket)
		if f != nil {
			f()
		}

		assert.Equal(t, err, nil, "error should be nil")

	}

	flowRecord := CreateFlowRecord(1, testSrcIP, testDstIP, 666, 80, policy.Accept, "")

	Convey("When the mode is RemoteConainter", t, func() {

		enforcer, mockCollector := createEnforcerWithPolicy(ctrl, constants.RemoteContainer)
		flowclient := mockflowclient.NewMockFlowClient(ctrl)
		flowclient.EXPECT().UpdateApplicationFlowMark(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(nil).AnyTimes()
		enforcer.conntrack = flowclient
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

		testThePackets(enforcer)

	})
}

func TestConnectionTrackerStateLocalContainer(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testThePackets := func(enforcer *Datapath) {

		PacketFlow := packetgen.NewTemplateFlow()
		_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
		So(err, ShouldBeNil)
		/*first packet in TCPFLOW slice is a syn packet*/
		Convey("When i pass a syn packet through the enforcer", func() {

			input, err := PacketFlow.GetFirstSynPacket().ToBytes()
			So(err, ShouldBeNil)

			tcpPacket, err := packet.New(0, input, "0", true)
			if err == nil && tcpPacket != nil {
				tcpPacket.UpdateIPv4Checksum()
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
			_, f, err := enforcer.processNetworkTCPPackets(outPacket)
			if f != nil {
				f()
			}
			So(err, ShouldBeNil)
			//Check after processing networksyn packet
			CheckAfterNetSynPacket(enforcer, tcpPacket, outPacket)

		})
		Convey("When i pass a SYN and SYN ACK packet through the enforcer", func() {

			input, err := PacketFlow.GetFirstSynPacket().ToBytes()
			So(err, ShouldBeNil)

			tcpPacket, err := packet.New(0, input, "0", true)
			if err == nil && tcpPacket != nil {
				tcpPacket.UpdateIPv4Checksum()
				tcpPacket.UpdateTCPChecksum()
			}
			_, err = enforcer.processApplicationTCPPackets(tcpPacket)
			So(err, ShouldBeNil)

			output := make([]byte, len(tcpPacket.GetTCPBytes()))
			copy(output, tcpPacket.GetTCPBytes())

			outPacket, err := packet.New(0, output, "0", true)
			So(err, ShouldBeNil)
			outPacket.Print(0, false)
			_, f, err := enforcer.processNetworkTCPPackets(outPacket)
			if f != nil {
				f()
			}
			So(err, ShouldBeNil)

			//Now lets send the synack packet from the server in response
			input, err = PacketFlow.GetFirstSynAckPacket().ToBytes()
			So(err, ShouldBeNil)

			tcpPacket, err = packet.New(0, input, "0", true)
			if err == nil && tcpPacket != nil {
				tcpPacket.UpdateIPv4Checksum()
				tcpPacket.UpdateTCPChecksum()
			}
			_, err = enforcer.processApplicationTCPPackets(tcpPacket)
			So(err, ShouldBeNil)

			output = make([]byte, len(tcpPacket.GetTCPBytes()))
			copy(output, tcpPacket.GetTCPBytes())

			outPacket, err = packet.New(0, output, "0", true)
			So(err, ShouldBeNil)
			outPacketcopy, _ := packet.New(0, output, "0", true)
			_, f, err = enforcer.processNetworkTCPPackets(outPacket)
			if f != nil {
				f()
			}
			So(err, ShouldBeNil)

			CheckAfterNetSynAckPacket(t, enforcer, outPacketcopy, outPacket)
		})

		Convey("When i pass a SYN and SYNACK and another ACK packet through the enforcer", func() {

			input, err := PacketFlow.GetFirstSynPacket().ToBytes()
			So(err, ShouldBeNil)
			tcpPacket, err := packet.New(0, input, "0", true)
			if err == nil && tcpPacket != nil {
				tcpPacket.UpdateIPv4Checksum()
				tcpPacket.UpdateTCPChecksum()
			}
			_, err = enforcer.processApplicationTCPPackets(tcpPacket)
			So(err, ShouldBeNil)

			output := make([]byte, len(tcpPacket.GetTCPBytes()))
			copy(output, tcpPacket.GetTCPBytes())

			outPacket, err := packet.New(0, output, "0", true)
			So(err, ShouldBeNil)
			_, f, err := enforcer.processNetworkTCPPackets(outPacket)
			if f != nil {
				f()
			}
			So(err, ShouldBeNil)

			//Now lets send the synack packet from the server in response
			input, err = PacketFlow.GetFirstSynAckPacket().ToBytes()
			So(err, ShouldBeNil)

			tcpPacket, err = packet.New(0, input, "0", true)
			if err == nil && tcpPacket != nil {
				tcpPacket.UpdateIPv4Checksum()
				tcpPacket.UpdateTCPChecksum()
			}
			_, err = enforcer.processApplicationTCPPackets(tcpPacket)
			So(err, ShouldBeNil)

			output = make([]byte, len(tcpPacket.GetTCPBytes()))
			copy(output, tcpPacket.GetTCPBytes())

			outPacket, err = packet.New(0, output, "0", true)
			So(err, ShouldBeNil)
			_, f, err = enforcer.processNetworkTCPPackets(outPacket)
			if f != nil {
				f()
			}
			So(err, ShouldBeNil)

			input, err = PacketFlow.GetFirstAckPacket().ToBytes()
			So(err, ShouldBeNil)

			tcpPacket, err = packet.New(0, input, "0", true)
			if err == nil && tcpPacket != nil {
				tcpPacket.UpdateIPv4Checksum()
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
			_, f, err = enforcer.processNetworkTCPPackets(outPacket)
			if f != nil {
				f()
			}
			So(err, ShouldBeNil)
		})
	}

	flowRecord := CreateFlowRecord(1, testSrcIP, testDstIP, 666, 80, policy.Accept, "")

	Convey("When the mode is RemoteConainter", t, func() {

		enforcer, mockCollector := createEnforcerWithPolicy(ctrl, constants.RemoteContainer)
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).AnyTimes()
		testThePackets(enforcer)

	})

	Convey("When the mode is LocalServer", t, func() {

		enforcer, mockCollector := createEnforcerWithPolicy(ctrl, constants.LocalServer)
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).AnyTimes()
		testThePackets(enforcer)

	})
}

func CheckAfterAppSynPacket(enforcer *Datapath, tcpPacket *packet.Packet) {

	appConn, _ := enforcer.tcpClient.Get(tcpPacket.L4FlowHash())
	So(appConn.GetState(), ShouldEqual, connection.TCPSynSend)
}

func CheckAfterNetSynPacket(enforcer *Datapath, tcpPacket, outPacket *packet.Packet) {

	appConn, _ := enforcer.tcpServer.Get(tcpPacket.L4FlowHash())
	So(appConn.GetState(), ShouldEqual, connection.TCPSynReceived)
}

func CheckAfterNetSynAckPacket(t *testing.T, enforcer *Datapath, tcpPacket, outPacket *packet.Packet) {

	netconn, _ := enforcer.tcpClient.Get(outPacket.L4ReverseFlowHash())
	So(netconn.GetState(), ShouldEqual, connection.TCPSynAckReceived)
}

func CheckAfterAppAckPacket(enforcer *Datapath, tcpPacket *packet.Packet) {

	appConn, _ := enforcer.tcpClient.Get(tcpPacket.L4FlowHash())
	So(appConn.GetState(), ShouldEqual, connection.TCPAckSend)
}

func CheckBeforeNetAckPacket(enforcer *Datapath, tcpPacket, outPacket *packet.Packet, isReplay bool) {

	appConn, _ := enforcer.tcpServer.Get(tcpPacket.L4FlowHash())
	if !isReplay {
		So(appConn.GetState(), ShouldEqual, connection.TCPSynAckSend)
	} else {
		So(appConn.GetState(), ShouldBeGreaterThan, connection.TCPSynAckSend)
	}
}

func TestCacheState(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	defer MockGetUDPRawSocket()()

	Convey("Given I create a new enforcer instance", t, func() {

		enforcer, secrets, mockTokenAccessor, mockCollector, mockDNS := NewWithMocks(ctrl, "serverID", constants.LocalServer, []string{"0.0.0.0/0"}, true)

		secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
		mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(2).Return([]byte("token"), nil).AnyTimes()
		mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).Times(2)
		mockDNS.EXPECT().StartDNSServer(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
		mockDNS.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Times(2)
		mockDNS.EXPECT().Unenforce(gomock.Any(), gomock.Any()).Times(1)
		mockDNS.EXPECT().SyncWithPlatformCache(gomock.Any(), gomock.Any()).Times(2)

		contextID := "123"

		puInfo := policy.NewPUInfo(contextID, "/ns1", common.ContainerPU)

		CounterReport := &collector.CounterReport{
			PUID:      puInfo.Policy.ManagementID(),
			Namespace: puInfo.Policy.ManagementNamespace(),
		}
		mockCollector.EXPECT().CollectCounterEvent(MyCounterMatcher(CounterReport)).Times(2)

		// Should fail: Not in cache
		err := enforcer.Unenforce(context.Background(), contextID)
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
		err = enforcer.Enforce(context.Background(), contextID, puInfo)
		if err != nil {
			t.Errorf("Expected no failure %s", err)
		}

		// Should  not fail:  Update
		err = enforcer.Enforce(context.Background(), contextID, puInfo)
		if err != nil {
			t.Errorf("Expected no failure %s", err)
		}

		// Should  not fail:  IP is valid
		err = enforcer.Unenforce(context.Background(), contextID)
		if err != nil {
			t.Errorf("Expected failure, no IP but passed %s", err)
		}
	})
}

func TestDoCreatePU(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	defer MockGetUDPRawSocket()()

	Convey("Given an initialized enforcer for Linux Processes", t, func() {

		defer MockGetUDPRawSocket()()

		enforcer, secrets, mockTokenAccessor, _, mockDNS := NewWithMocks(ctrl, "serverID", constants.LocalServer, []string{"0.0.0.0/0"}, true)

		secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
		mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
		mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)
		mockDNS.EXPECT().StartDNSServer(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
		mockDNS.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
		mockDNS.EXPECT().SyncWithPlatformCache(gomock.Any(), gomock.Any()).Times(1)

		contextID := "124"
		puInfo := policy.NewPUInfo(contextID, "/ns1", common.LinuxProcessPU)

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
			err := enforcer.Enforce(context.Background(), contextID, puInfo)

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

		enforcer, secrets, mockTokenAccessor, _, mockDNS := NewWithMocks(ctrl, "serverID", constants.LocalServer, []string{"0.0.0.0/0"}, true)

		secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
		mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
		mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)
		mockDNS.EXPECT().StartDNSServer(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
		mockDNS.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
		mockDNS.EXPECT().SyncWithPlatformCache(gomock.Any(), gomock.Any()).Times(1)

		contextID := "125"
		puInfo := policy.NewPUInfo(contextID, "/ns1", common.LinuxProcessPU)

		Convey("When I create a new PU without ports or mark", func() {
			err := enforcer.Enforce(context.Background(), contextID, puInfo)

			Convey("It should succeed", func() {
				So(err, ShouldBeNil)
				_, err := enforcer.puFromContextID.Get(contextID)
				So(err, ShouldBeNil)
				So(enforcer.puFromIP, ShouldBeNil)
			})
		})
	})

	Convey("Given an initialized enforcer for remote Linux Containers", t, func() {

		enforcer, secrets, mockTokenAccessor, _, mockDNS := NewWithMocks(ctrl, "serverID", constants.RemoteContainer, []string{"0.0.0.0/0"}, true)

		secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
		mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
		mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)
		mockDNS.EXPECT().StartDNSServer(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
		mockDNS.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
		mockDNS.EXPECT().SyncWithPlatformCache(gomock.Any(), gomock.Any()).Times(1)

		contextID := "126"
		puInfo := policy.NewPUInfo(contextID, "/ns1", common.ContainerPU)

		Convey("When I create a new PU without an IP", func() {
			err := enforcer.Enforce(context.Background(), contextID, puInfo)

			Convey("It should succeed ", func() {
				So(err, ShouldBeNil)
				So(enforcer.puFromIP, ShouldNotBeNil)
			})
		})
	})
}

func TestContextFromIP(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given an initialized enforcer for Linux Processes", t, func() {

		enforcer, _, _, _, _ := NewWithMocks(ctrl, "serverID", constants.RemoteContainer, []string{"0.0.0.0/0"}, true)

		puInfo := policy.NewPUInfo("SomePU", "/ns", common.ContainerPU)

		context, err := pucontext.NewPU("SomePU", puInfo, nil, 10*time.Second)
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
				markVal := strconv.Itoa(100)
				ctx, err := enforcer.contextFromIP(true, markVal, 0, packet.IPProtocolTCP)
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

	Convey("Given an initialized enforcer for HostPU", t, func() {

		enforcer, _, _, _, _ := NewWithMocks(ctrl, "serverID", constants.RemoteContainer, []string{"0.0.0.0/0"}, true)

		puInfo := policy.NewPUInfo("SomeHostPU", "/ns", common.HostPU)

		context, err := pucontext.NewPU("SomeHostPU", puInfo, nil, 10*time.Second)
		So(err, ShouldBeNil)

		enforcer.hostPU = context

		Convey("If I try to get context for app ICMP for HostPU it should succeed ", func() {
			ctx, err := enforcer.contextFromIP(true, "", 0, packet.IPProtocolICMP)
			So(err, ShouldBeNil)
			So(ctx, ShouldNotBeNil)
			So(ctx, ShouldEqual, context)
		})
		Convey("If I try to get context for net ICMP for HostPU it should succeed ", func() {
			ctx, err := enforcer.contextFromIP(false, "", 0, packet.IPProtocolICMP)
			So(err, ShouldBeNil)
			So(ctx, ShouldNotBeNil)
			So(ctx, ShouldEqual, context)
		})
		Convey("If I try to get context for another protocol it should not return host context ", func() {
			_, err := enforcer.contextFromIP(true, "", 0, packet.IPProtocolTCP)
			So(err, ShouldNotBeNil)
		})

	})
}

func TestInvalidPacket(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testThePackets := func(enforcer *Datapath) {

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
			outpacket.TCPDataDetach(binary.BigEndian.Uint16([]byte{0x0, p[32]})/4 - 20)
			So(err, ShouldBeNil)
			_, _, err = enforcer.processNetworkTCPPackets(outpacket)
			So(err, ShouldNotBeNil)
		}

	}

	flowRecord := CreateFlowRecord(1, testSrcIP, testDstIP, 666, 80, policy.Reject|policy.Log, collector.MissingToken)

	Convey("When the mode is RemoteConainter", t, func() {

		enforcer, mockCollector := createEnforcerWithPolicy(ctrl, constants.RemoteContainer)
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)
		testThePackets(enforcer)

	})

	Convey("When the mode is LocalServer", t, func() {

		enforcer, mockCollector := createEnforcerWithPolicy(ctrl, constants.LocalServer)
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)
		testThePackets(enforcer)

	})
}

func TestFlowReportingInvalidSyn(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testThePackets := func(enforcer *Datapath) {

		SIP := net.IPv4zero
		packetDiffers := false

		PacketFlow := packetgen.NewTemplateFlow()
		_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
		So(err, ShouldBeNil)
		for i := 0; i < PacketFlow.GetSynPackets().GetNumPackets(); i++ {

			start, err := PacketFlow.GetSynPackets().GetNthPacket(i).ToBytes()
			So(err, ShouldBeNil)
			oldPacket, err := packet.New(0, start, "0", true)
			if err == nil && oldPacket != nil {
				oldPacket.UpdateIPv4Checksum()
				oldPacket.UpdateTCPChecksum()
			}

			input, err := PacketFlow.GetSynPackets().GetNthPacket(i).ToBytes()
			So(err, ShouldBeNil)
			tcpPacket, err := packet.New(0, input, "0", true)
			if err == nil && tcpPacket != nil {
				tcpPacket.UpdateIPv4Checksum()
				tcpPacket.UpdateTCPChecksum()
			}

			if debug {
				fmt.Println("Input packet", i)
				tcpPacket.Print(0, false)
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
				tcpPacket.Print(0, false)
			}

			output := make([]byte, len(tcpPacket.GetTCPBytes()))
			copy(output, tcpPacket.GetTCPBytes())

			outPacket, errp := packet.New(0, output, "0", true)
			So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
			So(errp, ShouldBeNil)
			_, _, err = enforcer.processNetworkTCPPackets(outPacket)
			So(err, ShouldNotBeNil)

			if debug {
				fmt.Println("Output packet", i)
				outPacket.Print(0, false)
			}

			if !reflect.DeepEqual(oldPacket.GetTCPBytes(), outPacket.GetTCPBytes()) {
				packetDiffers = true
				fmt.Println("Error: packets dont match")
				fmt.Println("Input Packet")
				oldPacket.Print(0, false)
				fmt.Println("Output Packet")
				outPacket.Print(0, false)
				t.Errorf("Packet %d Input and output packet do not match", i)
				t.FailNow()
			}
		}

		Convey("Then I expect all the input and output packets (after encoding and decoding) to be same", func() {

			So(packetDiffers, ShouldEqual, false)
		})
	}

	flowRecord := CreateFlowRecord(1, testSrcIP, testDstIP, 666, 80, policy.Reject|policy.Log, collector.MissingToken)

	Convey("When the mode is RemoteConainter", t, func() {

		enforcer, mockCollector := createEnforcerWithPolicy(ctrl, constants.RemoteContainer)
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)
		testThePackets(enforcer)

	})

	Convey("When the mode is LocalServer", t, func() {

		enforcer, mockCollector := createEnforcerWithPolicy(ctrl, constants.LocalServer)
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)
		testThePackets(enforcer)

	})
}

func TestFlowReportingUptoInvalidSynAck(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testThePackets := func(enforcer *Datapath) {

		SIP := net.IPv4zero
		packetDiffers := false

		PacketFlow := packetgen.NewTemplateFlow()
		_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
		So(err, ShouldBeNil)
		for i := 0; i < PacketFlow.GetUptoFirstSynAckPacket().GetNumPackets(); i++ {
			start, err := PacketFlow.GetUptoFirstSynAckPacket().GetNthPacket(i).ToBytes()
			So(err, ShouldBeNil)

			oldPacket, err := packet.New(0, start, "0", true)
			if err == nil && oldPacket != nil {
				oldPacket.UpdateIPv4Checksum()
				oldPacket.UpdateTCPChecksum()
			}
			input, err := PacketFlow.GetUptoFirstSynAckPacket().GetNthPacket(i).ToBytes()
			So(err, ShouldBeNil)
			tcpPacket, err := packet.New(0, input, "0", true)
			if err == nil && tcpPacket != nil {
				tcpPacket.UpdateIPv4Checksum()
				tcpPacket.UpdateTCPChecksum()
			}

			if debug {
				fmt.Println("Input packet", i)
				tcpPacket.Print(0, false)
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
				tcpPacket.Print(0, false)
			}

			output := make([]byte, len(tcpPacket.GetTCPBytes()))
			copy(output, tcpPacket.GetTCPBytes())

			outPacket, errp := packet.New(0, output, "0", true)
			So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
			So(errp, ShouldBeNil)

			if PacketFlow.GetNthPacket(i).GetTCPSyn() && !PacketFlow.GetNthPacket(i).GetTCPAck() {
				_, _, err = enforcer.processNetworkTCPPackets(outPacket)
				So(err, ShouldBeNil)
			}
			if PacketFlow.GetNthPacket(i).GetTCPSyn() && PacketFlow.GetNthPacket(i).GetTCPAck() {
				_, _, err = enforcer.processNetworkTCPPackets(outPacket)
				So(err, ShouldNotBeNil)
			}

			if debug {
				fmt.Println("Output packet", i)
				outPacket.Print(0, false)
			}

			if !reflect.DeepEqual(oldPacket.GetTCPBytes(), outPacket.GetTCPBytes()) {
				packetDiffers = true
				fmt.Println("Error: packets dont match")
				fmt.Println("Input Packet")
				oldPacket.Print(0, false)
				fmt.Println("Output Packet")
				outPacket.Print(0, false)
				t.Errorf("Packet %d Input and output packet do not match", i)
				t.FailNow()
			}
		}

		Convey("Then I expect all the input and output packets (after encoding and decoding) to be same", func() {

			So(packetDiffers, ShouldEqual, false)
		})
	}

	flowRecord := CreateFlowRecord(1, testSrcIP, testDstIP, 666, 80, policy.Reject|policy.Log, "policy")

	Convey("When the mode is RemoteConainter", t, func() {

		enforcer, mockCollector := createEnforcerWithPolicy(ctrl, constants.RemoteContainer)
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)
		testThePackets(enforcer)

	})

	Convey("When the mode is LocalServer", t, func() {

		enforcer, mockCollector := createEnforcerWithPolicy(ctrl, constants.LocalServer)
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)
		testThePackets(enforcer)

	})
}

func TestForPacketsWithRandomFlags(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	debug = true

	defer MockGetUDPRawSocket()()

	testThePackets := func(enforcer *Datapath) {

		PacketFlow := packetgen.NewPacketFlow("aa:ff:aa:ff:aa:ff", "ff:aa:ff:aa:ff:aa", testSrcIP, testDstIP, 666, 80)
		_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGenerateGoodFlow)
		So(err, ShouldBeNil)

		count := PacketFlow.GetNumPackets()
		for i := 0; i < count; i++ {
			//Setting random TCP flags for all the packets
			PacketFlow.GetNthPacket(i).SetTCPCwr()
			PacketFlow.GetNthPacket(i).SetTCPPsh()
			PacketFlow.GetNthPacket(i).SetTCPEce()
			input, err := PacketFlow.GetNthPacket(i).ToBytes()
			So(err, ShouldBeNil)
			tcpPacket, err := packet.New(0, input, "0", true)
			if err == nil && tcpPacket != nil {
				tcpPacket.UpdateIPv4Checksum()
				tcpPacket.UpdateTCPChecksum()
			}

			if debug {
				fmt.Println("Input packet", i)
				tcpPacket.Print(0, false)
			}

			So(err, ShouldBeNil)
			So(tcpPacket, ShouldNotBeNil)

			SIP := tcpPacket.SourceAddress()

			if !reflect.DeepEqual(SIP, tcpPacket.DestinationAddress()) &&
				!reflect.DeepEqual(SIP, tcpPacket.SourceAddress()) {
				t.Error("Invalid Test Packet")
			}

			_, err = enforcer.processApplicationTCPPackets(tcpPacket)
			So(err, ShouldBeNil)

			if debug {
				fmt.Println("Intermediate packet", i)
				tcpPacket.Print(0, false)
			}

			output := make([]byte, len(tcpPacket.GetTCPBytes()))
			copy(output, tcpPacket.GetTCPBytes())

			outPacket, errp := packet.New(0, output, "0", true)
			So(len(tcpPacket.GetTCPBytes()), ShouldBeLessThanOrEqualTo, len(outPacket.GetTCPBytes()))
			So(errp, ShouldBeNil)

			_, f, err := enforcer.processNetworkTCPPackets(outPacket)
			if f != nil {
				f()
			}

			So(err, ShouldBeNil)

			if debug {
				fmt.Println("Output packet ", i)
				outPacket.Print(0, false)
			}
		}
	}

	flowRecord := CreateFlowRecord(1, testSrcIP, testDstIP, 666, 80, policy.Accept, "")

	Convey("When the mode is RemoteConainter", t, func() {

		enforcer, mockCollector := createEnforcerWithPolicy(ctrl, constants.RemoteContainer)
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)
		testThePackets(enforcer)

	})

	Convey("When the mode is LocalServer", t, func() {

		enforcer, mockCollector := createEnforcerWithPolicy(ctrl, constants.LocalServer)
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)
		testThePackets(enforcer)
	})
}

func TestPUPortCreation(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given I setup an enforcer", t, func() {

		defer MockGetUDPRawSocket()()

		enforcer, secrets, mockTokenAccessor, _, mockDNS := NewWithMocks(ctrl, "serverID1", constants.LocalServer, []string{"0.0.0.0/0"}, true)
		if enforcer == nil { // This avoids lint error SA5011: possible nil pointer dereference (staticcheck)
			So(enforcer != nil, ShouldBeTrue)
			return
		}

		enforcer.packetLogs = true

		secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
		mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
		mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)

		contextID := "1001"
		puInfo := policy.NewPUInfo(contextID, "/ns1", common.LinuxProcessPU)
		puInfo.Runtime.SetOptions(policy.OptionsType{
			CgroupMark: "100",
		})

		mockDNS.EXPECT().StartDNSServer(gomock.Any(), contextID, gomock.Any()).Times(1)
		mockDNS.EXPECT().Enforce(gomock.Any(), contextID, puInfo)
		mockDNS.EXPECT().SyncWithPlatformCache(gomock.Any(), gomock.Any()).Times(1)

		enforcer.Enforce(context.Background(), contextID, puInfo) // nolint
	})
}

func TestCollectTCPPacket(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given I setup an enforcer", t, func() {

		enforcer, secrets, mockTokenAccessor, mockCollector, _ := NewWithMocks(ctrl, "serverID1", constants.RemoteContainer, []string{"0.0.0.0/0"}, true)
		So(enforcer != nil, ShouldBeTrue)

		secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
		mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
		mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)

		contextID := "dummy"
		_, err := CreatePUContext(enforcer, contextID, "/ns1", common.ContainerPU, mockTokenAccessor)
		So(err, ShouldBeNil)

		tcpPacket, err := newPacket(1, packet.TCPSynMask, testSrcIP, testDstIP, srcPort, dstPort, true, false)
		So(err, ShouldBeNil)

		Convey("We setup tcp network packet tracing for this pu with incomplete state", func() {
			interval := 10 * time.Second
			err := enforcer.EnableDatapathPacketTracing(context.TODO(), contextID, packettracing.NetworkOnly, interval)
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
			err := enforcer.EnableDatapathPacketTracing(context.TODO(), contextID, packettracing.NetworkOnly, interval)
			So(err, ShouldBeNil)
			packetreport := collector.PacketReport{
				DestinationIP: tcpPacket.DestinationAddress().String(),
				SourceIP:      tcpPacket.SourceAddress().String(),
			}
			context, _ := enforcer.puFromContextID.Get(contextID)
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
			err := enforcer.EnableDatapathPacketTracing(context.TODO(), contextID, packettracing.NetworkOnly, interval)
			So(err, ShouldBeNil)
			packetreport := collector.PacketReport{
				DestinationIP: tcpPacket.DestinationAddress().String(),
				SourceIP:      tcpPacket.SourceAddress().String(),
			}
			context, _ := enforcer.puFromContextID.Get(contextID)
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

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given I setup an enforcer", t, func() {

		enforcer, secrets, mockTokenAccessor, _, _ := NewWithMocks(ctrl, "serverID1", constants.RemoteContainer, []string{"0.0.0.0/0"}, true)
		if enforcer == nil { // This avoids lint error SA5011: possible nil pointer dereference (staticcheck)
			So(enforcer != nil, ShouldBeTrue)
			return
		}

		secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
		mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
		mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)

		contextID := "dummy"
		_, err := CreatePUContext(enforcer, contextID, "/ns1", common.ContainerPU, mockTokenAccessor)
		So(err, ShouldBeNil)

		err = enforcer.EnableDatapathPacketTracing(context.TODO(), contextID, packettracing.ApplicationOnly, 10*time.Second)
		So(err, ShouldBeNil)
		_, err = enforcer.packetTracingCache.Get(contextID)
		So(err, ShouldBeNil)
	})
}

func Test_CheckCounterCollection(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	collectCounterInterval = 1 * time.Second
	Convey("Given I setup an enforcer", t, func() {

		Convey("So When enforcer exits", func() {

			enforcer, secrets, mockTokenAccessor, mockCollector, _ := NewWithMocks(ctrl, "serverID1", constants.RemoteContainer, []string{"0.0.0.0/0"}, true)
			So(enforcer != nil, ShouldBeTrue)

			secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
			mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
			mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)

			puContext, err := CreatePUContext(enforcer, "dummy", "/ns1", common.ContainerPU, mockTokenAccessor)
			So(err, ShouldBeNil)

			CounterReport := &collector.CounterReport{
				PUID:      puContext.ManagementID(),
				Namespace: puContext.ManagementNamespace(),
			}
			mockCollector.EXPECT().CollectCounterEvent(MyCounterMatcher(CounterReport)).MinTimes(1)

			ctx, cancel := context.WithCancel(context.Background())
			go enforcer.counterCollector(ctx)

			puErr := puContext.Counters().CounterError((counters.ErrNonPUTraffic), fmt.Errorf("error"))

			So(puErr, ShouldNotBeNil)
			cancel()
		})

		Convey("So When enforer exits and waits for stuff to exit", func() {
			enforcer, secrets, mockTokenAccessor, mockCollector, _ := NewWithMocks(ctrl, "serverID1", constants.RemoteContainer, []string{"0.0.0.0/0"}, true)
			So(enforcer != nil, ShouldBeTrue)

			secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
			mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
			mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)

			puContext, err := CreatePUContext(enforcer, "dummy", "/ns1", common.ContainerPU, mockTokenAccessor)
			So(err, ShouldBeNil)

			c := &collector.CounterReport{
				PUID:      puContext.ManagementID(),
				Namespace: puContext.ManagementNamespace(),
			}

			mockCollector.EXPECT().CollectCounterEvent(MyCounterMatcher(c)).MinTimes(1)

			ctx, cancel := context.WithCancel(context.Background())
			go enforcer.counterCollector(ctx)

			puErr := puContext.Counters().CounterError(counters.ErrNonPUTraffic, fmt.Errorf("error"))

			So(puErr, ShouldNotBeNil)
			cancel()
			<-time.After(5 * time.Second)

		})
		Convey("So When an error is reported and the enforcer waits for collection interval", func() {
			enforcer, secrets, mockTokenAccessor, mockCollector, _ := NewWithMocks(ctrl, "serverID1", constants.RemoteContainer, []string{"0.0.0.0/0"}, true)
			So(enforcer != nil, ShouldBeTrue)

			secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
			mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
			mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)

			puContext, err := CreatePUContext(enforcer, "dummy", "/ns1", common.ContainerPU, mockTokenAccessor)
			So(err, ShouldBeNil)

			c := &collector.CounterReport{
				PUID:      puContext.ManagementID(),
				Namespace: puContext.ManagementNamespace(),
			}

			mockCollector.EXPECT().CollectCounterEvent(MyCounterMatcher(c)).MinTimes(1)

			ctx, cancel := context.WithCancel(context.Background())
			go enforcer.counterCollector(ctx)
			puErr := puContext.Counters().CounterError(counters.ErrNonPUTraffic, fmt.Errorf("error"))
			So(puErr, ShouldNotBeNil)
			<-time.After(5 * collectCounterInterval)
			cancel()

		})

	})
}

func Test_CounterReportedOnAuthSetAppSyn(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given I setup an enforcer", t, func() {

		enforcer, secrets, mockTokenAccessor, _, _ := NewWithMocks(ctrl, "serverID1", constants.RemoteContainer, []string{"0.0.0.0/0"}, true)
		So(enforcer != nil, ShouldBeTrue)

		secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
		mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
		mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)
		mockTokenAccessor.EXPECT().Randomize(gomock.Any(), gomock.Any()).Times(2)

		context, err := CreatePUContext(enforcer, "dummy", "/ns1", common.ContainerPU, mockTokenAccessor)
		So(err, ShouldBeNil)

		p, err := newPacket(packet.PacketTypeApplication, packet.TCPSynMask, "1.1.1.1", "2.2.2.2", srcPort, dstPort, false, false)
		So(err, ShouldBeNil)
		conn := connection.NewTCPConnection(context, p)
		err = enforcer.processApplicationSynPacket(p, context, conn)
		So(err, ShouldBeNil)

		c := conn.Context.Counters().GetErrorCounters()
		So(c[counters.ErrAppSynAuthOptionSet], ShouldBeZeroValue)

		p, err = newPacket(packet.PacketTypeApplication, packet.TCPSynMask, "1.1.1.1", "2.2.2.2", srcPort, dstPort, true, false)
		So(err, ShouldBeNil)
		conn = connection.NewTCPConnection(context, p)
		err = enforcer.processApplicationSynPacket(p, context, conn)
		So(err, ShouldBeNil)

		c = conn.Context.Counters().GetErrorCounters()
		So(c[counters.ErrAppSynAuthOptionSet], ShouldEqual, 1)
	})
}

func Test_CounterOnSynCacheTimeout(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given I setup an enforcer", t, func() {

		enforcer, secrets, mockTokenAccessor, _, _ := NewWithMocks(ctrl, "serverID1", constants.RemoteContainer, []string{"0.0.0.0/0"}, true)
		if enforcer == nil { // This avoids lint error SA5011: possible nil pointer dereference (staticcheck)
			So(enforcer != nil, ShouldBeTrue)
			return
		}

		secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
		mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
		mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)
		mockTokenAccessor.EXPECT().Randomize(gomock.Any(), gomock.Any()).Times(1)

		context, err := CreatePUContext(enforcer, "dummy", "/ns1", common.ContainerPU, mockTokenAccessor)
		So(err, ShouldBeNil)

		p, err := newPacket(packet.PacketTypeApplication, packet.TCPSynMask, "1.1.1.1", "2.2.2.2", srcPort, dstPort, false, false)
		So(err, ShouldBeNil)

		// Update the connection timer for testing.
		conn := connection.NewTCPConnection(context, p)
		conn.ChangeConnectionTimeout(2 * time.Second)

		err = enforcer.processApplicationSynPacket(p, context, conn)
		So(err, ShouldBeNil)

		c := conn.Context.Counters().GetErrorCounters()
		So(c[counters.ErrTCPConnectionsExpired], ShouldBeZeroValue)

		// Wait for the connection to expire.
		time.Sleep(3 * time.Second)
		_, exists := enforcer.tcpClient.Get(p.L4FlowHash())
		if exists {
			t.Fail()
		}

		c = conn.Context.Counters().GetErrorCounters()
		So(c[counters.ErrTCPConnectionsExpired], ShouldEqual, 1)
	})
}

func Test_NOClaims(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given I setup an enforcer", t, func() {

		enforcer, _, _, mockCollector, _ := NewWithMocks(ctrl, "serverID1", constants.RemoteContainer, []string{"0.0.0.0/0"}, true)
		So(enforcer != nil, ShouldBeTrue)

		flowRecord := CreateFlowRecord(1, "1.1.1.1", "2.2.2.2", 2000, 80, policy.Reject|policy.Log, collector.PolicyDrop)
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

		context, err := CreatePUContext(enforcer, "dummy", "/ns1", common.ContainerPU, nil)
		So(err, ShouldBeNil)

		p, err := newPacket(packet.PacketTypeNetwork, packet.TCPSynAckMask, "2.2.2.2", "1.1.1.1", dstPort, srcPort, true, false)
		So(err, ShouldBeNil)

		conn := connection.NewTCPConnection(context, p)

		_, err = enforcer.processNetworkSynAckPacket(context, conn, p)
		So(err, ShouldNotBeNil)
	})
}

func newPacket(context uint64, tcpFlags uint8, src, dst string, srcPort, desPort uint16, addOptions bool, addPayload bool) (*packet.Packet, error) { //nolint

	p, err := packet.NewIpv4TCPPacket(context, tcpFlags, src, dst, srcPort, dstPort)
	if err != nil {
		return nil, err
	}

	p.SetTCPSeq(rand.Uint32())

	if addOptions {
		options := []byte{2 /*Maximum Segment Size*/, 4, 0x05, 0x8C, 34, enforcerconstants.TCPAuthenticationOptionBaseLen, 0, 0}
		buffer := append(p.GetBuffer(0), options...)
		err = p.UpdatePacketBuffer(buffer, uint16(len(options)))
	}

	if addPayload {
		buffer := append(p.GetBuffer(0), []byte("dummy payload")...)
		err = p.UpdatePacketBuffer(buffer, 0)
	}

	return p, err
}

func TestCheckConnectionDeletion(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given I setup an enforcer", t, func() {

		enforcer, secrets, mockTokenAccessor, _, _ := NewWithMocks(ctrl, "serverID1", constants.RemoteContainer, []string{"0.0.0.0/0"}, true)

		secrets.EXPECT().TransmittedKey().Return([]byte("dummy")).AnyTimes()
		secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
		mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
		mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)

		err := CreatePortPolicy(enforcer, "dummy", "/ns1", common.ContainerPU, mockTokenAccessor, "2", dstPort, dstPort)
		So(err, ShouldBeNil)

		tcpPacket, err := newPacket(1, packet.TCPSynMask, testSrcIP, testDstIP, srcPort, dstPort, true, false)
		So(err, ShouldBeNil)

		conn := &connection.TCPConnection{
			ServiceConnection: true,
			MarkForDeletion:   true,
		}

		hash := tcpPacket.L4FlowHash()
		enforcer.tcpClient.Put(hash, conn)

		tcpPacket.Mark = "2"

		conn1, err := enforcer.appSynRetrieveState(tcpPacket)
		So(err, ShouldBeNil)
		So(conn1.MarkForDeletion, ShouldBeFalse)

		enforcer.tcpServer.Put(hash, conn)
		_, err = enforcer.netSynRetrieveState(tcpPacket)
		So(err, ShouldBeNil)

		tcpSynAckPacket, err := newPacket(1, packet.TCPSynAckMask, testDstIP, testSrcIP, dstPort, srcPort, true, false)
		So(err, ShouldBeNil)

		_, err = enforcer.netSynAckRetrieveState(tcpSynAckPacket)
		So(err, ShouldNotBeNil)
		ShouldEqual(err, errNonPUTraffic)
	})
}

func TestNetSynRetrieveState(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Testing datapath.netSynRetrieveState
	// There are 4 different code branches in this functions

	Convey("Given I setup an enforcer", t, func() {

		defer MockGetUDPRawSocket()()

		enforcer, secrets, mockTokenAccessor, _, _ := NewWithMocks(ctrl, "serverID1", constants.LocalServer, []string{"0.0.0.0/0"}, true)

		secrets.EXPECT().TransmittedKey().Return([]byte("dummy")).AnyTimes()
		secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
		mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
		mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)

		err := CreatePortPolicy(enforcer, "123456", "/ns1", common.LinuxProcessPU, mockTokenAccessor, "2", 9000, 9000)
		So(err, ShouldBeNil)

		// Test the error case
		p, err := packet.NewIpv4TCPPacket(1, 0x2, "127.0.0.1", "127.0.0.1", 43758, 8000)
		So(err, ShouldBeNil)
		_, err = enforcer.netSynRetrieveState(p)
		So(err, ShouldNotBeNil)

		p, err = packet.NewIpv4TCPPacket(1, 0x2, "127.0.0.1", "127.0.0.1", 43758, 9000)
		So(err, ShouldBeNil)

		conn, err := enforcer.netSynRetrieveState(p)
		So(err, ShouldBeNil)

		enforcer.tcpServer.Put(p.L4FlowHash(), conn)

		So(conn.GetInitialSequenceNumber(), ShouldEqual, p.TCPSequenceNumber())
		Convey("I retry the same packet", func() {
			retryconn, err := enforcer.netSynRetrieveState(p)
			assert.Equal(t, err, nil, "error should be nil")
			assert.Equal(t, retryconn, conn, "connection should be same")
		})
		Convey("Then i modify the sequence number and retry the packet", func() {
			p.IncreaseTCPSeq(10)
			conn1, err := enforcer.netSynRetrieveState(p)
			So(err, ShouldBeNil)
			So(conn1.GetInitialSequenceNumber(), ShouldNotEqual, conn.GetInitialSequenceNumber())
			_, exists := enforcer.tcpServer.Get(p.L4FlowHash())
			if exists {
				t.Fail()
			}
		})

	})
}

func TestAppSynRetrieveState(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Testing datapath.appSynRetrieveState
	// There are 4 different code branches in the function

	Convey("Given I setup an enforcer", t, func() {

		defer MockGetUDPRawSocket()()

		enforcer, _, _, _, _ := NewWithMocks(ctrl, "serverID1", constants.LocalServer, []string{"0.0.0.0/0"}, true)

		err := CreatePortPolicy(enforcer, "testContextID", "/ns1", common.LinuxProcessPU, nil, "2", 9000, 9000)
		So(err, ShouldBeNil)

		// Create a Syn packet
		p, err := packet.NewIpv4TCPPacket(1, 0x2, "127.0.0.1", "127.0.0.1", 43758, 9000)
		So(err, ShouldBeNil)

		// The error case "PU context doesn't exist for this syn, return error"
		_, err = enforcer.appSynRetrieveState(p)
		So(err, ShouldNotBeNil)

		p.Mark = "2"

		conn, err := enforcer.appSynRetrieveState(p)
		So(err, ShouldBeNil)

		enforcer.tcpClient.Put(p.L4FlowHash(), conn)

		Convey("I replay the same packet", func() {
			retryconn, err := enforcer.appSynRetrieveState(p)
			So(err, ShouldBeNil)
			So(retryconn, ShouldNotBeNil)

		})
		Convey("I modify the sequence number and retransmit the packet", func() {
			p.IncreaseTCPSeq(10)
			retryconn, err := enforcer.appSynRetrieveState(p)
			So(retryconn, ShouldNotBeNil)
			So(err, ShouldBeNil)
			_, exists := enforcer.tcpClient.Get(p.L4FlowHash())
			if exists {
				t.Fail()
			}
		})
	})
}

func TestAppSynAckRetrieveState(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Testing datapath.appSynAckRetrieveState
	// There are 2 different code branches in this functions

	Convey("Given I setup an enforcer", t, func() {

		defer MockGetUDPRawSocket()()

		enforcer, _, _, _, _ := NewWithMocks(ctrl, "serverID1", constants.LocalServer, []string{"0.0.0.0/0"}, true)

		// Create a SynAck packet
		p, err := packet.NewIpv4TCPPacket(1, packet.TCPSynAckMask, "127.0.0.1", "127.0.0.1", 43758, 9000)
		So(err, ShouldBeNil)

		// The error case when nothing is in the cache
		_, err = enforcer.appSynAckRetrieveState(p)
		So(err, ShouldNotBeNil)

		// add connection to the cache
		enforcer.tcpServer.Put(p.L4ReverseFlowHash(), &connection.TCPConnection{})

		// Should be in the cache
		conn, err := enforcer.appSynAckRetrieveState(p)
		So(err, ShouldBeNil)
		So(conn, ShouldNotBeNil)
	})
}

func TestNetSynAckRetrieveState(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Testing datapath.netSynAckRetrieveState
	// There are 3 different code branches in this functions

	Convey("Given I setup an enforcer", t, func() {

		defer MockGetUDPRawSocket()()

		enforcer, _, _, _, _ := NewWithMocks(ctrl, "serverID1", constants.LocalServer, []string{"0.0.0.0/0"}, true)

		// Create a SynAck packet
		p, err := packet.NewIpv4TCPPacket(1, packet.TCPSynAckMask, "127.0.0.1", "127.0.0.1", 43758, 9000)
		So(err, ShouldBeNil)

		// The error case when nothing is in the cache
		_, err = enforcer.netSynAckRetrieveState(p)
		ShouldEqual(err, errNonPUTraffic)

		// add connection to the cache
		enforcer.tcpClient.Put(p.L4ReverseFlowHash(), &connection.TCPConnection{})

		// Should be in the cache
		conn, err := enforcer.netSynAckRetrieveState(p)
		So(err, ShouldBeNil)
		So(conn, ShouldNotBeNil)

		// Mark the connection as deleted
		conn.MarkForDeletion = true

		// We should get an error
		_, err = enforcer.netSynAckRetrieveState(p)
		ShouldEqual(err, errOutOfOrderSynAck)
	})
}

func TestAppRetrieveState(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Testing datapath.appRetrieveState
	// There are 6 branch conditions in this function.

	Convey("Given I setup an enforcer", t, func() {

		defer MockGetUDPRawSocket()()

		enforcer, _, _, _, _ := NewWithMocks(ctrl, "serverID1", constants.LocalServer, []string{"0.0.0.0/0"}, true)

		// Create a Rst packet
		p, err := packet.NewIpv4TCPPacket(1, packet.TCPRstMask, "127.0.0.1", "127.0.0.1", 43758, 9000)
		So(err, ShouldBeNil)

		// 1. We should get the errRstPacket error
		_, err = enforcer.appRetrieveState(p)
		ShouldEqual(err, errRstPacket)

		// Create a Syn packet
		p, err = packet.NewIpv4TCPPacket(1, packet.TCPSynMask, "127.0.0.1", "127.0.0.1", 43758, 9000)
		So(err, ShouldBeNil)

		// 2. We should get errNoConnection error
		_, err = enforcer.appRetrieveState(p)
		ShouldEqual(err, errNoConnection)

		// Create a Ack packet
		p, err = packet.NewIpv4TCPPacket(1, packet.TCPAckMask, "127.0.0.1", "127.0.0.1", 43758, 9000)
		So(err, ShouldBeNil)

		// 3. We should get error "No context in app processing"
		_, err = enforcer.appRetrieveState(p)
		ShouldResemble(err, errors.New("No context in app processing"))

		// Create port policy
		err = CreatePortPolicy(enforcer, "testContextID", "/ns1", common.LinuxProcessPU, nil, "2", 43758, 43758)
		So(err, ShouldBeNil)

		p.Mark = "2"

		// 4. We should get a connection object with UnknownState
		conn, err := enforcer.appRetrieveState(p)
		So(err, ShouldBeNil)
		So(conn, ShouldNotBeNil)
		ShouldEqual(conn.GetState(), connection.UnknownState)

		// add connection to the server cache
		connServer := &connection.TCPConnection{}
		enforcer.tcpServer.Put(p.L4ReverseFlowHash(), connServer)

		// 5. Should be in the cache
		conn, err = enforcer.appRetrieveState(p)
		So(err, ShouldBeNil)
		ShouldEqual(conn, connServer)

		// add connection to the client cache
		connClient := &connection.TCPConnection{}
		enforcer.tcpClient.Put(p.L4FlowHash(), connClient)

		// 6. Should be in the cache
		conn, err = enforcer.appRetrieveState(p)
		So(err, ShouldBeNil)
		ShouldEqual(conn, connClient)
	})
}

func TestNetRetrieveState(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Testing datapath.netRetrieveState
	// There are 7 branch conditions in this function.

	Convey("Given I setup an enforcer", t, func() {

		defer MockGetUDPRawSocket()()

		enforcer, _, _, _, _ := NewWithMocks(ctrl, "serverID1", constants.LocalServer, []string{"0.0.0.0/0"}, true)

		// Create a Rst packet
		p, err := packet.NewIpv4TCPPacket(1, packet.TCPRstMask, "127.0.0.1", "127.0.0.1", 43758, 9000)
		So(err, ShouldBeNil)

		// 1. We should get the errRstPacket error
		_, err = enforcer.netRetrieveState(p)
		ShouldEqual(err, errRstPacket)

		// Create a Syn packet
		p, err = packet.NewIpv4TCPPacket(1, packet.TCPSynMask, "127.0.0.1", "127.0.0.1", 43758, 9000)
		So(err, ShouldBeNil)

		// 2. We should get errNoConnection error
		_, err = enforcer.netRetrieveState(p)
		ShouldEqual(err, errNoConnection)

		// Create a Ack packet
		p, err = packet.NewIpv4TCPPacket(1, packet.TCPAckMask, "127.0.0.1", "127.0.0.1", 43758, 9000)
		So(err, ShouldBeNil)

		// 3. We should get error " TCP Port Not Found 9000"
		_, err = enforcer.netRetrieveState(p)
		ShouldResemble(err, errors.New(" TCP Port Not Found 9000"))

		// Create port policy
		err = CreatePortPolicy(enforcer, "testContextID", "/ns1", common.LinuxProcessPU, nil, "2", 9000, 9000)
		So(err, ShouldBeNil)

		p.Mark = "2"

		// 4. We should get a connection object with UnknownState
		conn, err := enforcer.netRetrieveState(p)
		So(err, ShouldBeNil)
		So(conn, ShouldNotBeNil)
		ShouldEqual(conn.GetState(), connection.UnknownState)

		// add connection to the server cache
		connServer := &connection.TCPConnection{}
		enforcer.tcpServer.Put(p.L4FlowHash(), connServer)

		// 5. Should be in the cache
		conn, err = enforcer.netRetrieveState(p)
		So(err, ShouldBeNil)
		ShouldEqual(conn, connServer)

		// add connection to the client cache
		connClient := &connection.TCPConnection{}
		enforcer.tcpClient.Put(p.L4ReverseFlowHash(), connClient)

		// 6. Should be in the cache
		conn, err = enforcer.netRetrieveState(p)
		So(err, ShouldBeNil)
		ShouldEqual(conn, connClient)

		// Change to a Rst packet
		p.SetTCPFlags(packet.TCPRstMask)

		// 7. Should be in the cache, but should get error errRstPacket
		_, err = enforcer.netRetrieveState(p)
		So(err, ShouldNotBeNil)
		ShouldEqual(err, errRstPacket)
	})
}

// This is to ensure that if we get tcp fo packet with no identity payload that we drop the packet
func TestProcessNetworkSynPacket(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I setup an enforcer", t, func() {

		defer MockGetUDPRawSocket()()

		enforcer, _, _, mockCollector, _ := NewWithMocks(ctrl, "serverID1", constants.LocalServer, []string{"0.0.0.0/0"}, true)

		flowRecord := CreateFlowRecord(1, testSrcIP, testDstIP, 43758, 80, policy.Reject|policy.Log, collector.MissingToken)
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

		Convey("So I received a packet with tcp fast open option set but no payload", func() {

			p, err := packet.NewIpv4TCPPacket(1, 0x2, testSrcIP, testDstIP, 43758, 80)
			So(err, ShouldBeNil)
			So(p, ShouldNotBeNil)

			// Add the fast open option
			buffer := append(p.GetBuffer(0), []byte{packet.TCPAuthenticationOption, enforcerconstants.TCPAuthenticationOptionBaseLen, 0, 0}...)
			err = p.UpdatePacketBuffer(buffer, 4)
			So(err, ShouldBeNil)

			err = p.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen)
			So(err, ShouldBeNil)
			So(p.IsEmptyTCPPayload(), ShouldBeTrue)

			context, err := CreatePUContext(enforcer, "dummyContext", "/ns1", common.LinuxProcessPU, nil)
			So(err, ShouldBeNil)
			So(context, ShouldNotBeNil)

			_, err = enforcer.processNetworkSynPacket(context, connection.NewTCPConnection(context, p), p)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestProcessNetworkSynAckPacket(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I setup an enforcer", t, func() {

		defer MockGetUDPRawSocket()()

		enforcer, _, _, mockCollector, _ := NewWithMocks(ctrl, "serverID1", constants.LocalServer, []string{"0.0.0.0/0"}, true)

		flowRecord1 := CreateFlowRecord(1, testDstIP, testSrcIP, 80, 43758, policy.Reject|policy.Log, collector.PolicyDrop)
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord1)).Times(1)

		flowRecord2 := CreateFlowRecord(1, testDstIP, testSrcIP, 80, 43758, policy.Accept, "")
		mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord2)).Times(1)

		Convey("So I received a packet with tcp fast open option set but no payload", func() {

			p, err := packet.NewIpv4TCPPacket(1, 0x2, testSrcIP, testDstIP, 43758, 80)
			So(err, ShouldBeNil)
			So(p, ShouldNotBeNil)

			// Add the fast open option
			buffer := append(p.GetBuffer(0), []byte{packet.TCPAuthenticationOption, enforcerconstants.TCPAuthenticationOptionBaseLen, 0, 0}...)

			err = p.UpdatePacketBuffer(buffer, 4)
			So(err, ShouldBeNil)

			err = p.CheckTCPAuthenticationOption(enforcerconstants.TCPAuthenticationOptionBaseLen)
			So(err, ShouldBeNil)
			So(p.IsEmptyTCPPayload(), ShouldBeTrue)

			context, err := CreatePUContext(enforcer, "dummyContext", "/ns1", common.LinuxProcessPU, nil)
			So(err, ShouldBeNil)
			So(context, ShouldNotBeNil)

			_, err = enforcer.processNetworkSynAckPacket(context, connection.NewTCPConnection(context, p), p)
			So(err, ShouldNotBeNil)

			Convey("Then i add ip acl rule.", func() {
				iprules := policy.IPRuleList{policy.IPRule{
					Addresses: []string{"10.1.10.76/32"},
					Ports:     []string{"43758"},
					Protocols: []string{constants.TCPProtoNum},
					Policy: &policy.FlowPolicy{
						Action:   policy.Accept,
						PolicyID: "tcp172/8"},
				}}
				err = context.UpdateApplicationACLs(iprules)
				So(err, ShouldBeNil)

				_, err = enforcer.processNetworkSynAckPacket(context, connection.NewTCPConnection(context, p), p)
				So(err, ShouldBeNil)
			})
		})

	})
}
