// +build linux

package nfqdatapath

import (
	"crypto/ecdsa"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/collector/mockcollector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets/mocksecrets"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

var (
	srcAddress        = net.ParseIP("1.1.1.1")
	srcPort    uint16 = 2000
	srcID             = "src5454"
	dstAddress        = net.ParseIP("2.2.2.2")
	dstPort    uint16 = 80
	dstID             = "dst4545"
)

func setupDatapath(ctrl *gomock.Controller, collector collector.EventCollector) *Datapath {

	defer MockGetUDPRawSocket()()

	secrets := mocksecrets.NewMockSecrets(ctrl)
	secrets.EXPECT().AckSize().Return(uint32(300)).AnyTimes()
	secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
	secrets.EXPECT().TransmittedKey().Return([]byte("dummy")).AnyTimes()

	return newWithDefaults(ctrl, "serverID", collector, secrets, constants.RemoteContainer, []string{"1._,1.1.1/31"}, false)
}

func generateCommonTestData(action policy.ActionType, oaction policy.ObserveActionType) (*packet.Packet, *connection.TCPConnection, *connection.UDPConnection, *pucontext.PUContext, *policy.FlowPolicy) { // nolint

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
		dp := setupDatapath(ctrl, mockCollector)

		Convey("Then datapath should not be nil", func() {
			So(dp, ShouldNotBeNil)
		})

		Convey("Then check reportAcceptedFlow", func() {

			src, dst := generateTestEndpoints(false)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      *src,
				Destination: *dst,
				Action:      policy.Accept,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, conn, _, context, policy := generateCommonTestData(policy.Accept, policy.ObserveNone)

			dp.reportAcceptedFlow(p, conn, srcID, dstID, context, policy, policy, false)
		})

		Convey("Then check reportAcceptedFlow with same src dst ID", func() {

			src, dst := generateTestEndpoints(false)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      *src,
				Destination: *dst,
				Action:      policy.Accept | policy.Log,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, conn, _, context, policy := generateCommonTestData(policy.Accept|policy.Log, policy.ObserveNone)

			dp.reportAcceptedFlow(p, conn, srcID, srcID, context, policy, policy, false)
		})

		Convey("Then check reportAcceptedFlow with reverse", func() {

			src, dst := generateTestEndpoints(true)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      *src,
				Destination: *dst,
				Action:      policy.Accept,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, conn, _, context, policy := generateCommonTestData(policy.Accept, policy.ObserveNone)

			dp.reportAcceptedFlow(p, conn, srcID, dstID, context, policy, policy, true)
		})
	})
}

func TestReportExternalServiceFlow(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	Convey("Given I setup datapath", t, func() {
		dp := setupDatapath(ctrl, mockCollector)

		Convey("Then datapath should not be nil", func() {
			So(dp, ShouldNotBeNil)
		})

		Convey("Then check reportAcceptedFlow", func() {

			src, dst := generateTestEndpoints(false)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      *src,
				Destination: *dst,
				Action:      policy.Accept,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, _, _, context, policy := generateCommonTestData(policy.Accept, policy.ObserveNone)

			dp.reportExternalServiceFlow(context, policy, policy, true, p)
		})

		Convey("Then check reportAcceptedFlow reverse", func() {

			src, dst := generateTestEndpoints(false)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      *dst,
				Destination: *src,
				Action:      policy.Reject,
				DropReason:  collector.PolicyDrop,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, _, _, context, policy := generateCommonTestData(policy.Reject, policy.ObserveContinue)

			dp.reportReverseExternalServiceFlow(context, policy, policy, false, p)
		})
	})
}

func TestReportUDPAcceptedFlow(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	Convey("Given I setup datapath", t, func() {
		dp := setupDatapath(ctrl, mockCollector)

		Convey("Then datapath should not be nil", func() {
			So(dp, ShouldNotBeNil)
		})

		Convey("Then check reportAcceptedFlow", func() {

			src, dst := generateTestEndpoints(false)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      *src,
				Destination: *dst,
				Action:      policy.Accept,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, _, conn, context, policy := generateCommonTestData(policy.Accept, policy.ObserveNone)

			dp.reportUDPAcceptedFlow(p, conn, srcID, dstID, context, policy, policy, false)
		})

		Convey("Then check reportAcceptedFlow with reverse", func() {

			src, dst := generateTestEndpoints(true)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      *src,
				Destination: *dst,
				Action:      policy.Accept,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, _, conn, context, policy := generateCommonTestData(policy.Accept, policy.ObserveNone)

			dp.reportUDPAcceptedFlow(p, conn, srcID, dstID, context, policy, policy, true)
		})
	})
}

func TestReportRejectedFlow(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	Convey("Given I setup datapath", t, func() {
		dp := setupDatapath(ctrl, mockCollector)

		Convey("Then datapath should not be nil", func() {
			So(dp, ShouldNotBeNil)
		})

		Convey("Then check reportRejectedFlow", func() {

			src, dst := generateTestEndpoints(false)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      *src,
				Destination: *dst,
				Action:      policy.Reject,
				DropReason:  collector.PolicyDrop,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, conn, _, context, policy := generateCommonTestData(policy.Reject, policy.ObserveNone)

			dp.reportRejectedFlow(p, conn, srcID, dstID, context, collector.PolicyDrop, policy, policy, false)
		})

		Convey("Then check reportRejectedFlow with report and packet policy nil", func() {

			src, dst := generateTestEndpoints(false)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      *src,
				Destination: *dst,
				Action:      policy.Reject | policy.Log,
				DropReason:  collector.PolicyDrop,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, conn, _, context, _ := generateCommonTestData(policy.Reject|policy.Log, policy.ObserveNone)

			dp.reportRejectedFlow(p, conn, srcID, dstID, context, collector.PolicyDrop, nil, nil, false)
		})

		Convey("Then check reportRejectedFlow with reverse", func() {

			src, dst := generateTestEndpoints(true)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      *src,
				Destination: *dst,
				Action:      policy.Reject,
				DropReason:  collector.PolicyDrop,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, conn, _, context, policy := generateCommonTestData(policy.Reject, policy.ObserveNone)

			dp.reportRejectedFlow(p, conn, srcID, dstID, context, collector.PolicyDrop, policy, policy, true)
		})
	})
}

func TestReportUDPRejectedFlow(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	Convey("Given I setup datapath", t, func() {
		dp := setupDatapath(ctrl, mockCollector)

		Convey("Then datapath should not be nil", func() {
			So(dp, ShouldNotBeNil)
		})

		Convey("Then check reportRejectedFlow", func() {

			src, dst := generateTestEndpoints(false)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      *src,
				Destination: *dst,
				Action:      policy.Reject,
				DropReason:  collector.PolicyDrop,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, _, conn, context, policy := generateCommonTestData(policy.Reject, policy.ObserveNone)

			dp.reportUDPRejectedFlow(p, conn, srcID, dstID, context, collector.PolicyDrop, policy, policy, false)
		})

		Convey("Then check reportRejectedFlow with policy and packet policy nil", func() {

			src, dst := generateTestEndpoints(false)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      *src,
				Destination: *dst,
				Action:      policy.Reject | policy.Log,
				DropReason:  collector.PolicyDrop,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, _, conn, context, _ := generateCommonTestData(policy.Reject|policy.Log, policy.ObserveNone)

			dp.reportUDPRejectedFlow(p, conn, srcID, dstID, context, collector.PolicyDrop, nil, nil, false)
		})

		Convey("Then check reportRejectedFlow with reverse", func() {

			src, dst := generateTestEndpoints(true)

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      *src,
				Destination: *dst,
				Action:      policy.Reject,
				DropReason:  collector.PolicyDrop,
			}

			mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

			p, _, conn, context, policy := generateCommonTestData(policy.Reject, policy.ObserveNone)

			dp.reportUDPRejectedFlow(p, conn, srcID, dstID, context, collector.PolicyDrop, policy, policy, true)
		})
	})
}

func TestReportDefaultEndpoint(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)

	Convey("Given I setup datapath", t, func() {
		dp := setupDatapath(ctrl, mockCollector)

		Convey("Then datapath should not be nil", func() {
			So(dp, ShouldNotBeNil)
		})

		Convey("Then check reportRejectedFlow with dest ID set to default", func() {

			src, dst := generateTestEndpoints(false)
			src.Type = collector.EndPointTypePU
			dst.ID = collector.DefaultEndPoint
			dst.Type = collector.EndPointTypeExternalIP

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      *src,
				Destination: *dst,
				Action:      policy.Reject,
				DropReason:  collector.PolicyDrop,
			}

			mockCollector.EXPECT().CollectFlowEvent(EndpointTypeMatcher(&flowRecord)).Times(1)

			p, conn, _, context, policy := generateCommonTestData(policy.Reject, policy.ObserveNone)

			dp.reportRejectedFlow(p, conn, src.ID, dst.ID, context, collector.PolicyDrop, policy, policy, false)
		})

		Convey("Then check reportAcceptedFlow with src ID set to default", func() {

			src, dst := generateTestEndpoints(false)
			dst.Type = collector.EndPointTypePU
			src.ID = collector.DefaultEndPoint
			src.Type = collector.EndPointTypeExternalIP

			flowRecord := collector.FlowRecord{
				Count:       1,
				Source:      *src,
				Destination: *dst,
				Action:      policy.Accept,
			}

			mockCollector.EXPECT().CollectFlowEvent(EndpointTypeMatcher(&flowRecord)).Times(1)

			p, conn, _, context, policy := generateCommonTestData(policy.Accept, policy.ObserveNone)

			dp.reportAcceptedFlow(p, conn, src.ID, dst.ID, context, policy, policy, false)
		})
	})
}
