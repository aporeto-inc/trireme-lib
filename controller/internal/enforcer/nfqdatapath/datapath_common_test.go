package nfqdatapath

import (
	"context"
	"crypto/ecdsa"
	"time"

	"github.com/blang/semver"
	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/collector/mockcollector"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	enforcerconstants "go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/dnsproxy/mockdnsproxy"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor/mocktokenaccessor"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/flowtracking/mockflowclient"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pkiverifier"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets/mocksecrets"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/tokens"
	"go.aporeto.io/enforcerd/trireme-lib/controller/runtime"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cache"
	"go.aporeto.io/enforcerd/trireme-lib/utils/portspec"
)

const (
	testSrcIP = "10.1.10.76"
	testDstIP = "164.67.228.152"
)

var (
	debug bool
)

func procSetValueMock(procName string, value int) error {
	return nil
}

// NewWithDefaults create a new data path with most things used by default
func newWithDefaults(
	ctrl *gomock.Controller,
	serverID string,
	collector collector.EventCollector,
	secrets secrets.Secrets,
	mode constants.ModeType,
	targetNetworks []string,
	testExpirationNotifier bool,
) *Datapath {

	// Override so that you don't have to run as root
	procSetValuePtr = procSetValueMock

	mockTokenAccessor := mocktokenaccessor.NewMockTokenAccessor(ctrl)
	flowclient := mockflowclient.NewMockFlowClient(ctrl)
	puFromContextID := cache.NewCache("puFromContextID")
	mockDNS := mockdnsproxy.NewMockDNSProxy(ctrl)

	mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
	mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
	mockTokenAccessor.EXPECT().CreateSynAckPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
	mockTokenAccessor.EXPECT().Randomize(gomock.Any(), gomock.Any()).AnyTimes()
	mockTokenAccessor.EXPECT().ParseAckToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mockTokenAccessor.EXPECT().ParsePacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(
		func(privateKey, data, secrets, c, b interface{}) interface{} {

			claims := c.(*tokens.ConnectionClaims)
			claims.T = policy.NewTagStore()
			claims.T.AppendKeyValue(enforcerconstants.TransmitterLabel, "value")
			return nil
		},
	).Return(nil, &claimsheader.ClaimsHeader{}, &pkiverifier.PKIControllerInfo{}, []byte("remoteNonce"), "", false, nil).AnyTimes()

	mockDNS.EXPECT().StartDNSServer(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockDNS.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockDNS.EXPECT().SyncWithPlatformCache(gomock.Any(), gomock.Any()).AnyTimes()

	e := New(
		false,
		nil,
		collector,
		serverID,
		10*time.Minute,
		secrets,
		mode,
		"/proc",
		500*time.Millisecond,
		false,
		mockTokenAccessor,
		puFromContextID,
		&runtime.Configuration{TCPTargetNetworks: targetNetworks},
		false,
		semver.Version{},
		policy.None,
	)

	e.conntrack = flowclient
	e.dnsProxy = mockDNS

	if testExpirationNotifier {
		e.tcpConnectionExpirationNotifier = testConnectionExpirationNotifier
	}

	return e
}

// NewWithMocks create a new data path using mock objects
func NewWithMocks(
	ctrl *gomock.Controller,
	serverID string,
	mode constants.ModeType,
	targetNetworks []string,
	testExpirationNotifier bool,
) (*Datapath, *mocksecrets.MockSecrets, *mocktokenaccessor.MockTokenAccessor,
	*mockcollector.MockEventCollector, *mockdnsproxy.MockDNSProxy) {

	// Override so that you don't have to run as root
	procSetValuePtr = procSetValueMock

	secrets := mocksecrets.NewMockSecrets(ctrl)
	tokenAccessor := mocktokenaccessor.NewMockTokenAccessor(ctrl)
	collector := mockcollector.NewMockEventCollector(ctrl)
	flowclient := mockflowclient.NewMockFlowClient(ctrl)
	puFromContextID := cache.NewCache("puFromContextID")
	dnsproxy := mockdnsproxy.NewMockDNSProxy(ctrl)

	secrets.EXPECT().AckSize().Return(uint32(300)).Times(1)

	e := New(
		false,
		nil,
		collector,
		serverID,
		10*time.Minute,
		secrets,
		mode,
		"/proc",
		500*time.Millisecond,
		false,
		tokenAccessor,
		puFromContextID,
		&runtime.Configuration{TCPTargetNetworks: targetNetworks},
		false,
		semver.Version{},
		policy.None,
	)

	e.conntrack = flowclient
	e.dnsProxy = dnsproxy

	if testExpirationNotifier {
		e.tcpConnectionExpirationNotifier = testConnectionExpirationNotifier
	}

	return e, secrets, tokenAccessor, collector, dnsproxy
}

func testConnectionExpirationNotifier(conn *connection.TCPConnection) {

	conn.Cleanup()
}

// MockGetUDPRawSocket mocks the GetUDPRawSocket function. Usage "defer MockGetUDPRawSocket()()"
func MockGetUDPRawSocket() func() {
	prevRawSocket := GetUDPRawSocket
	GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
		return nil, nil
	}
	return func() {
		GetUDPRawSocket = prevRawSocket
	}
}

// CreatePUContext creates a policy
func CreatePUContext(enforcer *Datapath, contextID, namespace string, puType common.PUType, tokenAccessor tokenaccessor.TokenAccessor) (*pucontext.PUContext, error) {
	puInfo := policy.NewPUInfo(contextID, namespace, puType)
	context, err := pucontext.NewPU(contextID, puInfo, tokenAccessor, 10*time.Second)
	if err != nil {
		return nil, err
	}
	enforcer.puFromContextID.AddOrUpdate(contextID, context) // nolint
	return context, nil
}

// CreatePortPolicy creates a port range policy
func CreatePortPolicy(enforcer *Datapath, contextID, namespace string, puType common.PUType, tokenAccessor tokenaccessor.TokenAccessor, mark string, portMin, portMax uint16) error {

	context, err := CreatePUContext(enforcer, contextID, namespace, puType, tokenAccessor)
	if err != nil {
		return err
	}

	err = enforcer.puFromMark.Add(mark, context)
	if err != nil {
		return err
	}

	portspec, err := portspec.NewPortSpec(portMin, portMax, contextID)
	if err != nil {
		return err
	}
	enforcer.contextIDFromTCPPort.AddPortSpec(portspec)
	return nil
}

// CreateFlowRecord creates a basic flow report
func CreateFlowRecord(count int, srcIP, destIP string, srcPort, destPort uint16, action policy.ActionType, dropReason string) collector.FlowRecord {
	var flowRecord collector.FlowRecord
	var srcEndPoint collector.EndPoint
	var dstEndPoint collector.EndPoint

	srcEndPoint.IP = srcIP
	srcEndPoint.Port = srcPort

	dstEndPoint.IP = destIP
	dstEndPoint.Port = destPort

	flowRecord.Count = count
	flowRecord.Source = srcEndPoint
	flowRecord.Destination = dstEndPoint
	flowRecord.Action = action
	flowRecord.DropReason = dropReason
	return flowRecord
}

func createEnforcerWithPolicy(ctrl *gomock.Controller, mode constants.ModeType) (*Datapath, *mockcollector.MockEventCollector) {

	puInfo1, puInfo2 := createPolicies(testSrcIP, testDstIP)
	So(puInfo1, ShouldNotBeNil)
	So(puInfo2, ShouldNotBeNil)

	enforcer, mockTokenAccessor := createEnforcer(ctrl, mode)

	err := enforcer.Enforce(context.Background(), puInfo1.ContextID, puInfo1)
	So(err, ShouldBeNil)

	err = enforcer.Enforce(context.Background(), puInfo2.ContextID, puInfo2)
	So(err, ShouldBeNil)

	return enforcer, mockTokenAccessor
}

func createEnforcer(ctrl *gomock.Controller, mode constants.ModeType) (*Datapath, *mockcollector.MockEventCollector) {

	enforcer, secrets, mockTokenAccessor, mockCollector, mockDNS := NewWithMocks(ctrl, "serverID", mode, []string{"0.0.0.0/0"}, true)
	So(enforcer != nil, ShouldBeTrue)

	secrets.EXPECT().EncodingKey().Return(&ecdsa.PrivateKey{}).AnyTimes()
	mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
	mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
	mockTokenAccessor.EXPECT().CreateSynAckPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil).AnyTimes()
	mockTokenAccessor.EXPECT().Randomize(gomock.Any(), gomock.Any()).AnyTimes()
	mockTokenAccessor.EXPECT().ParseAckToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mockTokenAccessor.EXPECT().ParsePacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(
		func(privateKey, data, secrets, c, b interface{}) interface{} {

			claims := c.(*tokens.ConnectionClaims)
			claims.T = policy.NewTagStore()
			claims.T.AppendKeyValue(enforcerconstants.TransmitterLabel, "value")
			return nil
		},
	).Return(nil, &claimsheader.ClaimsHeader{}, &pkiverifier.PKIControllerInfo{}, []byte("remoteNonce"), "", false, nil).AnyTimes()

	mockDNS.EXPECT().StartDNSServer(gomock.Any(), gomock.Any(), gomock.Any()).Times(2)
	mockDNS.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Times(2)
	mockDNS.EXPECT().SyncWithPlatformCache(gomock.Any(), gomock.Any()).Times(2)
	return enforcer, mockCollector
}

func createPolicies(srcIP, dstIP string) (*policy.PUInfo, *policy.PUInfo) {
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

	puID1 := "SomeProcessingUnitId1"
	puID2 := "SomeProcessingUnitId2"

	puIP1 := dstIP
	puIP2 := srcIP

	// Create ProcessingUnit 1
	puInfo1 := policy.NewPUInfo(puID1, "/ns1", common.ContainerPU)

	ip1 := policy.ExtendedMap{}
	ip1["bridge"] = puIP1
	puInfo1.Runtime.SetIPAddresses(ip1)
	ipl1 := policy.ExtendedMap{policy.DefaultNamespace: puIP1}
	puInfo1.Policy.SetIPAddresses(ipl1)
	puInfo1.Policy.AddIdentityTag(enforcerconstants.TransmitterLabel, "value")
	puInfo1.Policy.AddReceiverRules(tagSelector)

	// Create processing unit 2
	puInfo2 := policy.NewPUInfo(puID2, "/ns2", common.ContainerPU)
	ip2 := policy.ExtendedMap{"bridge": puIP2}
	puInfo2.Runtime.SetIPAddresses(ip2)
	ipl2 := policy.ExtendedMap{policy.DefaultNamespace: puIP2}
	puInfo2.Policy.SetIPAddresses(ipl2)
	puInfo2.Policy.AddIdentityTag(enforcerconstants.TransmitterLabel, "value")
	puInfo2.Policy.AddReceiverRules(tagSelector)

	return puInfo1, puInfo2
}
