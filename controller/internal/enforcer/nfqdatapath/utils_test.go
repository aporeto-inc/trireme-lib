package nfqdatapath

import (
	"fmt"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/collector/mockcollector"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/policy"
)

var (
	srcAddress        = net.ParseIP("1.1.1.1")
	srcPort    uint16 = 2000
	srcID             = "src5454"
	dstAddress        = net.ParseIP("2.2.2.2")
	dstPort    uint16 = 80
	dstID             = "dst4545"
)

func setupDatapath(collector collector.EventCollector) *Datapath {

	_, secret, err := secrets.CreateCompactPKITestSecrets()
	fmt.Println("ERROR IS ", err)

	// mock the call
	prevRawSocket := GetUDPRawSocket
	defer func() {
		GetUDPRawSocket = prevRawSocket
	}()
	GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
		return nil, nil
	}
	return NewWithDefaults("serverID", collector, nil, secret, constants.RemoteContainer, "/proc", []string{"1._,1.1.1/31"})
}

func generateCommonTestData(action policy.ActionType) (*packet.Packet, *connection.TCPConnection, *connection.UDPConnection, *pucontext.PUContext, *policy.FlowPolicy) {

	p := packet.TestGetTCPPacket(srcAddress, dstAddress, srcPort, dstPort)

	tcpConn := &connection.TCPConnection{}
	udpConn := &connection.UDPConnection{}
	puContext := &pucontext.PUContext{}
	policy := &policy.FlowPolicy{Action: action}

	return p, tcpConn, udpConn, puContext, policy
}

func generateTestEndpoints(reverse bool) (*collector.EndPoint, *collector.EndPoint) {

	src := &collector.EndPoint{
		IP:   srcAddress.String(),
		Port: srcPort,
		ID:   srcID,
	}
	dst := &collector.EndPoint{
		IP:   dstAddress.String(),
		Port: dstPort,
		ID:   dstID,
	}

	if reverse {
		return dst, src
	}

	return src, dst
}

func TestReportAcceptedFlow(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	Convey("Given I setup datapath", t, func() {
		dp := setupDatapath(mockCollector)

		Convey("Then datapath should not be nil", func() {
			So(dp, ShouldNotBeNil)
		})

		Convey("Then check reportAcceptedFlow", func() {

			src, dst := generateTestEndpoints(false)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      src,
				Destination: dst,
				Action:      policy.Accept,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, conn, _, context, policy := generateCommonTestData(policy.Accept)

			dp.reportAcceptedFlow(p, conn, srcID, dstID, context, policy, policy, false)
		})

		Convey("Then check reportAcceptedFlow with reverse", func() {

			src, dst := generateTestEndpoints(true)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      src,
				Destination: dst,
				Action:      policy.Accept,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, conn, _, context, policy := generateCommonTestData(policy.Accept)

			dp.reportAcceptedFlow(p, conn, srcID, dstID, context, policy, policy, true)
		})
	})
}

func TestReportUDPAcceptedFlow(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	Convey("Given I setup datapath", t, func() {
		dp := setupDatapath(mockCollector)

		Convey("Then datapath should not be nil", func() {
			So(dp, ShouldNotBeNil)
		})

		Convey("Then check reportAcceptedFlow", func() {

			src, dst := generateTestEndpoints(false)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      src,
				Destination: dst,
				Action:      policy.Accept,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, _, conn, context, policy := generateCommonTestData(policy.Accept)

			dp.reportUDPAcceptedFlow(p, conn, srcID, dstID, context, policy, policy, false)
		})

		Convey("Then check reportAcceptedFlow with reverse", func() {

			src, dst := generateTestEndpoints(true)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      src,
				Destination: dst,
				Action:      policy.Accept,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, _, conn, context, policy := generateCommonTestData(policy.Accept)

			dp.reportUDPAcceptedFlow(p, conn, srcID, dstID, context, policy, policy, true)
		})
	})
}

func TestReportRejectedFlow(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	Convey("Given I setup datapath", t, func() {
		dp := setupDatapath(mockCollector)

		Convey("Then datapath should not be nil", func() {
			So(dp, ShouldNotBeNil)
		})

		Convey("Then check reportRejectedFlow", func() {

			src, dst := generateTestEndpoints(false)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      src,
				Destination: dst,
				Action:      policy.Reject,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, conn, _, context, policy := generateCommonTestData(policy.Reject)

			dp.reportRejectedFlow(p, conn, srcID, dstID, context, collector.PolicyDrop, policy, policy, false)
		})

		Convey("Then check reportRejectedFlow with reverse", func() {

			src, dst := generateTestEndpoints(true)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      src,
				Destination: dst,
				Action:      policy.Reject,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, conn, _, context, policy := generateCommonTestData(policy.Reject)

			dp.reportRejectedFlow(p, conn, srcID, dstID, context, collector.PolicyDrop, policy, policy, true)
		})
	})
}

func TestReportUDPRejectedFlow(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	Convey("Given I setup datapath", t, func() {
		dp := setupDatapath(mockCollector)

		Convey("Then datapath should not be nil", func() {
			So(dp, ShouldNotBeNil)
		})

		Convey("Then check reportRejectedFlow", func() {

			src, dst := generateTestEndpoints(false)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      src,
				Destination: dst,
				Action:      policy.Reject,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, _, conn, context, policy := generateCommonTestData(policy.Reject)

			dp.reportUDPRejectedFlow(p, conn, srcID, dstID, context, collector.PolicyDrop, policy, policy, false)
		})

		Convey("Then check reportRejectedFlow with reverse", func() {

			src, dst := generateTestEndpoints(true)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      src,
				Destination: dst,
				Action:      policy.Reject,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, _, conn, context, policy := generateCommonTestData(policy.Reject)

			dp.reportUDPRejectedFlow(p, conn, srcID, dstID, context, collector.PolicyDrop, policy, policy, true)
		})
	})
}
