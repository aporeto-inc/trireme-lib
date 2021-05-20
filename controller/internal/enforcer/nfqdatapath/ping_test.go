// +build linux

package nfqdatapath

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghedo/go.pkt/layers"
	gpacket "github.com/ghedo/go.pkt/packet"
	"github.com/ghedo/go.pkt/packet/ipv4"
	"github.com/ghedo/go.pkt/packet/tcp"
	"github.com/golang/mock/gomock"
	"github.com/mitchellh/copystructure"
	"github.com/stretchr/testify/require"
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/collector/mockcollector"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	enforcerconstants "go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor/mocktokenaccessor"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/tokens"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/gaia"
	"go.aporeto.io/underwater/core/tagutils"
)

var (
	testPU1CtxID  = "pu1abc"
	testPU1NS     = "/ns1"
	testPU1NSHash = ""
	testPU2CtxID  = "pu2abc"
	testPU2NS     = "/ns2"
	testPU2NSHash = ""
	srcCtrl       = "srcctrl"
	dstCtrl       = "dstctrl"

	sip                 = net.ParseIP("192.168.100.1").To4()
	dip                 = net.ParseIP("172.17.0.2").To4()
	spt          uint16 = 2020
	dpt          uint16 = 80
	seqnum       uint32 = 123456
	duration            = "20ms"
	c                   = &fakeConn{}
	appListening int32  = 0
)

func switchAppListening(enable bool) {

	var state int32
	if enable {
		state = 1
	}

	atomic.StoreInt32(&appListening, state)
}

func init() {
	if hash, err := tagutils.Hash(testPU1NS); err == nil {
		testPU1NSHash = hash
	}

	if hash, err := tagutils.Hash(testPU2NS); err == nil {
		testPU2NSHash = hash
	}

	srcip = func(_ net.IP) (net.IP, error) {
		return sip, nil
	}
	dial = func(_, _ net.IP) (PingConn, error) {
		return c, nil
	}
	bind = func(tcpConn *connection.TCPConnection) (uint16, error) {
		tcpConn.PingConfig.SetSocketFd(8)
		return spt, nil
	}
	close = func(tcpConn *connection.TCPConnection) error {
		tcpConn.PingConfig.SetSocketClosed(true)
		return nil
	}
	randUint32 = func() uint32 {
		return seqnum
	}
	since = func(_ time.Time) time.Duration {
		d, _ := time.ParseDuration(duration)
		return d
	}

	isAppListening = func(port uint16) (bool, error) {
		if atomic.LoadInt32(&appListening) == 1 {
			return true, nil
		}
		return false, nil
	}
}

func setupDatapathAndPUs(ctrl *gomock.Controller, collector collector.EventCollector, tokenAccessor tokenaccessor.TokenAccessor) (*Datapath, *fakeConn, error) {

	dp := setupDatapath(ctrl, collector)
	dp.tokenAccessor = tokenAccessor

	pu1info := policy.NewPUInfo(testPU1CtxID, testPU1NS, common.ContainerPU)
	pu1info.Policy = policy.NewPUPolicy(
		testPU1CtxID,
		testPU1NS,
		policy.Police,
		nil,
		nil,
		nil,
		nil,
		nil,
		policy.NewTagStoreFromSlice([]string{"x=y"}),
		nil,
		nil,
		nil,
		0,
		0,
		nil,
		nil,
		nil,
		policy.EnforcerMapping,
		policy.Reject|policy.Log,
		policy.Reject|policy.Log,
	)

	if err := dp.Enforce(context.Background(), testPU1CtxID, pu1info); err != nil {
		return nil, nil, err
	}

	pu2info := policy.NewPUInfo(testPU2CtxID, testPU2NS, common.ContainerPU)
	pu2info.Policy = policy.NewPUPolicy(
		testPU2CtxID,
		testPU2NS,
		policy.Police,
		nil,
		nil,
		nil,
		nil,
		nil,
		policy.NewTagStoreFromSlice([]string{"a=b"}),
		nil,
		nil,
		nil,
		0,
		0,
		nil,
		nil,
		nil,
		policy.EnforcerMapping,
		policy.Reject|policy.Log,
		policy.Reject|policy.Log,
	)

	if err := dp.Enforce(context.Background(), testPU2CtxID, pu2info); err != nil {
		return nil, nil, err
	}

	return dp, c, nil
}

func wrapIP(d []byte, swap bool, changeSeqNum bool, flags tcp.Flags) ([]byte, error) {

	ipPacket := ipv4.Make()
	ipPacket.SrcAddr = sip
	ipPacket.DstAddr = dip
	if swap {
		ipPacket.SrcAddr = dip
		ipPacket.DstAddr = sip
	}
	ipPacket.Protocol = ipv4.TCP

	p, err := layers.UnpackAll(d, gpacket.TCP)
	if err != nil {
		return nil, err
	}

	tcpPacket, ok := p.(*tcp.Packet)
	if !ok {
		return nil, errors.New("not a tcp packet")
	}

	if flags != 0 {
		if flags != tcpPacket.Flags {
			return nil, fmt.Errorf("Expected: %s, Actual: %s", flags.String(), tcpPacket.Flags.String())
		}
	}

	if swap {
		tcpPacket.SrcPort = dpt
		tcpPacket.DstPort = spt
	}

	if changeSeqNum {
		tcpPacket.Seq = 111111
	}

	// pack the layers together.
	buf, err := layers.Pack(ipPacket, tcpPacket)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func Test_ValidPing(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)
	mockTokenAccessor := mocktokenaccessor.NewMockTokenAccessor(ctrl)
	mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(3).Return([]byte("token"), nil).AnyTimes()
	mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(3).Return([]byte("token"), nil)
	dp, conn, err := setupDatapathAndPUs(ctrl, mockCollector, mockTokenAccessor)
	require.Nil(t, err)
	require.NotNil(t, dp)

	item, err := dp.puFromContextID.Get(testPU1CtxID)
	require.Nil(t, err)
	require.NotNil(t, item)
	puctx1 := item.(*pucontext.PUContext)

	item, err = dp.puFromContextID.Get(testPU2CtxID)
	require.Nil(t, err)
	require.NotNil(t, item)
	puctx2 := item.(*pucontext.PUContext)

	pc := &policy.PingConfig{
		ID:                "5e9e38ad39483e772044095e",
		IP:                dip,
		Port:              dpt,
		Iterations:        1,
		TargetTCPNetworks: true,
		ExcludedNetworks:  false,
	}

	pingPayload := &policy.PingPayload{
		PingID:               pc.ID,
		IterationID:          0,
		ApplicationListening: false,
		NamespaceHash:        testPU1NSHash,
	}

	puctx1.UpdateApplicationACLs( // nolint: errcheck
		policy.IPRuleList{
			policy.IPRule{
				Addresses: []string{"0.0.0.0/0"},
				Ports:     []string{"1:65535"},
				Protocols: []string{"6", "17"},
				Policy: &policy.FlowPolicy{
					Action:   policy.Accept,
					PolicyID: "extnetidabc",
				},
			},
		},
	)

	//	mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)

	err = dp.Ping(context.Background(), testPU1CtxID, pc)
	require.Nil(t, err)

	// NetSyn
	ipPacket, err := wrapIP(conn.data(), false, false, tcp.Syn)
	require.Nil(t, err)

	p, err := packet.New(packet.PacketTypeNetwork, ipPacket, "0", false)
	require.Nil(t, err)
	require.NotNil(t, p)
	payloadSize := len(p.ReadTCPData())
	tcpConn := connection.NewTCPConnection(puctx2, p)
	tcpConn.SourceController = srcCtrl
	pkt := &policy.FlowPolicy{Action: policy.Accept, PolicyID: "abc"}

	ts := policy.NewTagStore()
	ts.AppendKeyValue(enforcerconstants.TransmitterLabel, testPU1CtxID)
	claims := &tokens.ConnectionClaims{
		P: pingPayload,
		T: ts,
	}

	pr := &collector.PingReport{
		PingID:               pc.ID,
		IterationID:          0,
		Type:                 gaia.PingProbeTypeRequest,
		PUID:                 testPU2CtxID,
		RemotePUID:           testPU1CtxID,
		Namespace:            testPU2NS,
		FourTuple:            "192.168.100.1:172.17.0.2:2020:80",
		RTT:                  "",
		Protocol:             6,
		ServiceType:          "L3",
		PayloadSize:          payloadSize,
		PayloadSizeType:      gaia.PingProbePayloadSizeTypeReceived,
		PolicyID:             "abc",
		PolicyAction:         policy.Accept,
		AgentVersion:         "0.0.0",
		ApplicationListening: false,
		RemoteEndpointType:   collector.EndPointTypePU,
		SeqNum:               seqnum,
		TargetTCPNetworks:    true,
		ExcludedNetworks:     false,
		Claims:               []string{"a=b"},
		ClaimsType:           gaia.PingProbeClaimsTypeTransmitted,
		RemoteNamespace:      testPU1NSHash,
		RemoteNamespaceType:  gaia.PingProbeRemoteNamespaceTypeHash,
		ACLPolicyID:          "",
		ACLPolicyAction:      policy.ActionType(0),
		RemoteController:     srcCtrl,
		IsServer:             true,
	}

	mockCollector.EXPECT().CollectPingEvent(pr).Times(1)
	copiedData, err := copystructure.Copy(pingPayload)
	synAckPayload := copiedData.(*policy.PingPayload)
	synAckPayload.NamespaceHash = testPU2NSHash
	require.Nil(t, err)
	mockTokenAccessor.EXPECT().CreateSynAckPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)

	oldsynAckDelay := synAckDelay
	synAckDelay = 1 * time.Second
	defer func() {
		synAckDelay = oldsynAckDelay
	}()

	err = dp.processPingNetSynPacket(puctx2, tcpConn, p, payloadSize, pkt, claims)
	require.Equal(t, errDropPingNetSyn, err)

	time.Sleep(2 * time.Second)

	// NetSynAck
	ipPacket, err = wrapIP(conn.data(), true, false, tcp.Syn|tcp.Ack)
	require.Nil(t, err)

	p, err = packet.New(packet.PacketTypeNetwork, ipPacket, "0", false)
	require.Nil(t, err)
	require.NotNil(t, p)

	item1, exists := dp.tcpClient.Get(p.L4ReverseFlowHash())
	if !exists {
		t.Fail()
	}

	tcpConn = item1
	tcpConn.DestinationController = dstCtrl

	pkt = &policy.FlowPolicy{Action: policy.Accept, PolicyID: "abc"}

	ts = policy.NewTagStore()
	ts.AppendKeyValue(enforcerconstants.TransmitterLabel, testPU2CtxID)
	claims = &tokens.ConnectionClaims{
		P: pingPayload,
		T: ts,
	}

	pr = &collector.PingReport{
		PingID:               pc.ID,
		IterationID:          0,
		Type:                 gaia.PingProbeTypeResponse,
		PUID:                 testPU1CtxID,
		RemotePUID:           testPU2CtxID,
		Namespace:            testPU1NS,
		FourTuple:            "172.17.0.2:192.168.100.1:80:2020",
		RTT:                  duration,
		Protocol:             6,
		ServiceType:          "L3",
		PayloadSize:          payloadSize,
		PayloadSizeType:      gaia.PingProbePayloadSizeTypeReceived,
		PolicyID:             "abc",
		PolicyAction:         policy.Accept,
		AgentVersion:         "0.0.0",
		ApplicationListening: false,
		RemoteEndpointType:   collector.EndPointTypePU,
		SeqNum:               seqnum,
		TargetTCPNetworks:    true,
		ExcludedNetworks:     false,
		Claims:               []string{"x=y"},
		ClaimsType:           gaia.PingProbeClaimsTypeTransmitted,
		RemoteNamespace:      testPU2NSHash,
		RemoteNamespaceType:  gaia.PingProbeRemoteNamespaceTypeHash,
		ACLPolicyID:          "extnetidabc",
		ACLPolicyAction:      policy.Accept,
		RemoteController:     dstCtrl,
	}

	mockCollector.EXPECT().CollectPingEvent(pr).Times(1)

	claims.P.NamespaceHash = testPU2NSHash
	err = dp.processPingNetSynAckPacket(puctx1, tcpConn, p, payloadSize, pkt, claims, false)
	require.Equal(t, errDropPingNetSynAck, err)
}

func Test_ValidPingAppListening(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer func() {
		switchAppListening(false)
		ctrl.Finish()
	}()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)
	mockTokenAccessor := mocktokenaccessor.NewMockTokenAccessor(ctrl)

	mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(3).Return([]byte("token"), nil).AnyTimes()
	mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(3).Return([]byte("token"), nil)

	dp, conn, err := setupDatapathAndPUs(ctrl, mockCollector, mockTokenAccessor)
	require.Nil(t, err)
	require.NotNil(t, dp)

	item, err := dp.puFromContextID.Get(testPU1CtxID)
	require.Nil(t, err)
	require.NotNil(t, item)
	puctx1 := item.(*pucontext.PUContext)

	item, err = dp.puFromContextID.Get(testPU2CtxID)
	require.Nil(t, err)
	require.NotNil(t, item)
	puctx2 := item.(*pucontext.PUContext)

	pc := &policy.PingConfig{
		ID:                "5e9e38ad39483e772044095e",
		IP:                dip,
		Port:              dpt,
		Iterations:        1,
		TargetTCPNetworks: true,
		ExcludedNetworks:  false,
	}

	pingPayload := &policy.PingPayload{
		PingID:               pc.ID,
		IterationID:          0,
		ApplicationListening: false,
		NamespaceHash:        testPU1NSHash,
	}

	puctx1.UpdateApplicationACLs( // nolint: errcheck
		policy.IPRuleList{
			policy.IPRule{
				Addresses: []string{"0.0.0.0/0"},
				Ports:     []string{"1:65535"},
				Protocols: []string{"6", "17"},
				Policy: &policy.FlowPolicy{
					Action:   policy.Accept,
					PolicyID: "extnetidabc",
				},
			},
		},
	)

	err = dp.Ping(context.Background(), testPU1CtxID, pc)
	require.Nil(t, err)

	// NetSyn
	ipPacket, err := wrapIP(conn.data(), false, false, tcp.Syn)
	require.Nil(t, err)

	p, err := packet.New(packet.PacketTypeNetwork, ipPacket, "0", false)
	require.Nil(t, err)
	require.NotNil(t, p)
	payloadSize := len(p.ReadTCPData())
	tcpConn := connection.NewTCPConnection(puctx2, p)
	tcpConn.SourceController = srcCtrl
	pkt := &policy.FlowPolicy{Action: policy.Accept, PolicyID: "abc"}

	ts := policy.NewTagStore()
	ts.AppendKeyValue(enforcerconstants.TransmitterLabel, testPU1CtxID)
	claims := &tokens.ConnectionClaims{
		P: pingPayload,
		T: ts,
	}

	pr := &collector.PingReport{
		PingID:               pc.ID,
		IterationID:          0,
		Type:                 gaia.PingProbeTypeRequest,
		PUID:                 testPU2CtxID,
		RemotePUID:           testPU1CtxID,
		Namespace:            testPU2NS,
		FourTuple:            "192.168.100.1:172.17.0.2:2020:80",
		RTT:                  "",
		Protocol:             6,
		ServiceType:          "L3",
		PayloadSize:          payloadSize,
		PayloadSizeType:      gaia.PingProbePayloadSizeTypeReceived,
		PolicyID:             "abc",
		PolicyAction:         policy.Accept,
		AgentVersion:         "0.0.0",
		ApplicationListening: false,
		RemoteEndpointType:   collector.EndPointTypePU,
		SeqNum:               seqnum,
		TargetTCPNetworks:    true,
		ExcludedNetworks:     false,
		Claims:               []string{"a=b"},
		ClaimsType:           gaia.PingProbeClaimsTypeTransmitted,
		RemoteNamespace:      testPU1NSHash,
		RemoteNamespaceType:  gaia.PingProbeRemoteNamespaceTypeHash,
		ACLPolicyID:          "",
		ACLPolicyAction:      policy.ActionType(0),
		RemoteController:     srcCtrl,
		IsServer:             true,
	}

	mockCollector.EXPECT().CollectPingEvent(pr).Times(1)

	oldsynAckDelay := synAckDelay
	synAckDelay = 1 * time.Second
	defer func() {
		synAckDelay = oldsynAckDelay
	}()

	switchAppListening(true)
	err = dp.processPingNetSynPacket(puctx2, tcpConn, p, payloadSize, pkt, claims)
	require.Nil(t, err)

	tcpConn.PingConfig.SetApplicationListening(true)

	time.Sleep(2 * time.Second)

	// NetSynAck
	ipPacket, err = wrapIP(conn.data(), true, false, 0)
	require.Nil(t, err)

	p, err = packet.New(packet.PacketTypeNetwork, ipPacket, "0", false)
	require.Nil(t, err)
	require.NotNil(t, p)

	item1, exists := dp.tcpClient.Get(p.L4ReverseFlowHash())
	if !exists {
		t.Fail()
	}

	tcpConn = item1
	tcpConn.DestinationController = dstCtrl

	pkt = &policy.FlowPolicy{Action: policy.Accept, PolicyID: "abc"}

	ts = policy.NewTagStore()
	ts.AppendKeyValue(enforcerconstants.TransmitterLabel, testPU2CtxID)
	claims = &tokens.ConnectionClaims{
		P: pingPayload,
		T: ts,
	}

	pr = &collector.PingReport{
		PingID:               pc.ID,
		IterationID:          0,
		Type:                 gaia.PingProbeTypeResponse,
		PUID:                 testPU1CtxID,
		RemotePUID:           testPU2CtxID,
		Namespace:            testPU1NS,
		FourTuple:            "172.17.0.2:192.168.100.1:80:2020",
		RTT:                  duration,
		Protocol:             6,
		ServiceType:          "L3",
		PayloadSize:          payloadSize,
		PayloadSizeType:      gaia.PingProbePayloadSizeTypeReceived,
		PolicyID:             "abc",
		PolicyAction:         policy.Accept,
		AgentVersion:         "0.0.0",
		ApplicationListening: true,
		RemoteEndpointType:   collector.EndPointTypePU,
		SeqNum:               seqnum,
		TargetTCPNetworks:    true,
		ExcludedNetworks:     false,
		Claims:               []string{"x=y"},
		ClaimsType:           gaia.PingProbeClaimsTypeTransmitted,
		RemoteNamespace:      testPU2NSHash,
		RemoteNamespaceType:  gaia.PingProbeRemoteNamespaceTypeHash,
		ACLPolicyID:          "extnetidabc",
		ACLPolicyAction:      policy.Accept,
		RemoteController:     dstCtrl,
	}

	mockCollector.EXPECT().CollectPingEvent(pr).Times(1)

	claims.P.ApplicationListening = true
	claims.P.NamespaceHash = testPU2NSHash
	err = dp.processPingNetSynAckPacket(puctx1, tcpConn, p, payloadSize, pkt, claims, false)
	require.Equal(t, errDropPingNetSynAck, err)
}

func Test_ValidPingAppListeningNoReply(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer func() {
		switchAppListening(false)
		ctrl.Finish()
	}()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)
	mockTokenAccessor := mocktokenaccessor.NewMockTokenAccessor(ctrl)
	mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(3).Return([]byte("token"), nil).AnyTimes()
	mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2).Return([]byte("token"), nil)

	dp, conn, err := setupDatapathAndPUs(ctrl, mockCollector, mockTokenAccessor)
	require.Nil(t, err)
	require.NotNil(t, dp)

	item, err := dp.puFromContextID.Get(testPU1CtxID)
	require.Nil(t, err)
	require.NotNil(t, item)
	puctx1 := item.(*pucontext.PUContext)

	item, err = dp.puFromContextID.Get(testPU2CtxID)
	require.Nil(t, err)
	require.NotNil(t, item)
	puctx2 := item.(*pucontext.PUContext)

	pc := &policy.PingConfig{
		ID:                "5e9e38ad39483e772044095e",
		IP:                dip,
		Port:              dpt,
		Iterations:        1,
		TargetTCPNetworks: true,
		ExcludedNetworks:  false,
	}

	pingPayload := &policy.PingPayload{
		PingID:               pc.ID,
		IterationID:          0,
		ApplicationListening: false,
		NamespaceHash:        testPU1NSHash,
	}

	puctx1.UpdateApplicationACLs( // nolint: errcheck
		policy.IPRuleList{
			policy.IPRule{
				Addresses: []string{"0.0.0.0/0"},
				Ports:     []string{"1:65535"},
				Protocols: []string{"6", "17"},
				Policy: &policy.FlowPolicy{
					Action:   policy.Accept,
					PolicyID: "extnetidabc",
				},
			},
		},
	)

	mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)

	err = dp.Ping(context.Background(), testPU1CtxID, pc)
	require.Nil(t, err)

	// NetSyn
	ipPacket, err := wrapIP(conn.data(), false, false, tcp.Syn)
	require.Nil(t, err)

	p, err := packet.New(packet.PacketTypeNetwork, ipPacket, "0", false)
	require.Nil(t, err)
	require.NotNil(t, p)
	payloadSize := len(p.ReadTCPData())
	tcpConn := connection.NewTCPConnection(puctx2, p)
	tcpConn.SourceController = srcCtrl
	pkt := &policy.FlowPolicy{Action: policy.Accept, PolicyID: "abc"}

	ts := policy.NewTagStore()
	ts.AppendKeyValue(enforcerconstants.TransmitterLabel, testPU1CtxID)
	claims := &tokens.ConnectionClaims{
		P: pingPayload,
		T: ts,
	}

	pr := &collector.PingReport{
		PingID:               pc.ID,
		IterationID:          0,
		Type:                 gaia.PingProbeTypeRequest,
		PUID:                 testPU2CtxID,
		RemotePUID:           testPU1CtxID,
		Namespace:            testPU2NS,
		FourTuple:            "192.168.100.1:172.17.0.2:2020:80",
		RTT:                  "",
		Protocol:             6,
		ServiceType:          "L3",
		PayloadSize:          payloadSize,
		PayloadSizeType:      gaia.PingProbePayloadSizeTypeReceived,
		PolicyID:             "abc",
		PolicyAction:         policy.Accept,
		AgentVersion:         "0.0.0",
		ApplicationListening: false,
		RemoteEndpointType:   collector.EndPointTypePU,
		SeqNum:               seqnum,
		TargetTCPNetworks:    true,
		ExcludedNetworks:     false,
		Claims:               []string{"a=b"},
		ClaimsType:           gaia.PingProbeClaimsTypeTransmitted,
		RemoteNamespace:      testPU1NSHash,
		RemoteNamespaceType:  gaia.PingProbeRemoteNamespaceTypeHash,
		ACLPolicyID:          "",
		ACLPolicyAction:      policy.ActionType(0),
		RemoteController:     srcCtrl,
		IsServer:             true,
	}

	mockCollector.EXPECT().CollectPingEvent(pr).Times(1)
	copiedData, err := copystructure.Copy(pingPayload)
	synAckPayload := copiedData.(*policy.PingPayload)
	synAckPayload.NamespaceHash = testPU2NSHash
	require.Nil(t, err)
	mockTokenAccessor.EXPECT().CreateSynAckPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)

	oldsynAckDelay := synAckDelay
	synAckDelay = 1 * time.Second
	defer func() {
		synAckDelay = oldsynAckDelay
	}()

	switchAppListening(true)
	err = dp.processPingNetSynPacket(puctx2, tcpConn, p, payloadSize, pkt, claims)
	require.Nil(t, err)

	time.Sleep(2 * time.Second)

	// NetSynAck
	ipPacket, err = wrapIP(conn.data(), true, false, tcp.Syn|tcp.Ack)
	require.Nil(t, err)

	p, err = packet.New(packet.PacketTypeNetwork, ipPacket, "0", false)
	require.Nil(t, err)
	require.NotNil(t, p)

	item1, exists := dp.tcpClient.Get(p.L4ReverseFlowHash())
	if !exists {
		t.Fail()
	}

	tcpConn = item1
	tcpConn.DestinationController = dstCtrl

	pkt = &policy.FlowPolicy{Action: policy.Accept, PolicyID: "abc"}

	ts = policy.NewTagStore()
	ts.AppendKeyValue(enforcerconstants.TransmitterLabel, testPU2CtxID)
	claims = &tokens.ConnectionClaims{
		P: pingPayload,
		T: ts,
	}

	pr = &collector.PingReport{
		PingID:               pc.ID,
		IterationID:          0,
		Type:                 gaia.PingProbeTypeResponse,
		PUID:                 testPU1CtxID,
		RemotePUID:           testPU2CtxID,
		Namespace:            testPU1NS,
		FourTuple:            "172.17.0.2:192.168.100.1:80:2020",
		RTT:                  duration,
		Protocol:             6,
		ServiceType:          "L3",
		PayloadSize:          payloadSize,
		PayloadSizeType:      gaia.PingProbePayloadSizeTypeReceived,
		PolicyID:             "abc",
		PolicyAction:         policy.Accept,
		AgentVersion:         "0.0.0",
		ApplicationListening: false,
		RemoteEndpointType:   collector.EndPointTypePU,
		SeqNum:               seqnum,
		TargetTCPNetworks:    true,
		ExcludedNetworks:     false,
		Claims:               []string{"x=y"},
		ClaimsType:           gaia.PingProbeClaimsTypeTransmitted,
		RemoteNamespace:      testPU2NSHash,
		RemoteNamespaceType:  gaia.PingProbeRemoteNamespaceTypeHash,
		ACLPolicyID:          "extnetidabc",
		ACLPolicyAction:      policy.Accept,
		RemoteController:     dstCtrl,
	}

	mockCollector.EXPECT().CollectPingEvent(pr).Times(1)

	claims.P.NamespaceHash = testPU2NSHash
	err = dp.processPingNetSynAckPacket(puctx1, tcpConn, p, payloadSize, pkt, claims, false)
	require.Equal(t, errDropPingNetSynAck, err)
}

func Test_ValidPingReject(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)
	mockTokenAccessor := mocktokenaccessor.NewMockTokenAccessor(ctrl)
	mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(3).Return([]byte("token"), nil).AnyTimes()
	mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(3).Return([]byte("token"), nil)

	dp, conn, err := setupDatapathAndPUs(ctrl, mockCollector, mockTokenAccessor)
	require.Nil(t, err)
	require.NotNil(t, dp)

	item, err := dp.puFromContextID.Get(testPU1CtxID)
	require.Nil(t, err)
	require.NotNil(t, item)
	puctx1 := item.(*pucontext.PUContext)

	item, err = dp.puFromContextID.Get(testPU2CtxID)
	require.Nil(t, err)
	require.NotNil(t, item)
	puctx2 := item.(*pucontext.PUContext)

	pc := &policy.PingConfig{
		ID:                "5e9e38ad39483e772044095e",
		IP:                dip,
		Port:              dpt,
		Iterations:        1,
		TargetTCPNetworks: true,
		ExcludedNetworks:  false,
	}

	pingPayload := &policy.PingPayload{
		PingID:               pc.ID,
		IterationID:          0,
		ApplicationListening: false,
		NamespaceHash:        testPU1NSHash,
	}

	puctx1.UpdateApplicationACLs( // nolint: errcheck
		policy.IPRuleList{
			policy.IPRule{
				Addresses: []string{"0.0.0.0/0"},
				Ports:     []string{"1:65535"},
				Protocols: []string{"6", "17"},
				Policy: &policy.FlowPolicy{
					Action:   policy.Accept,
					PolicyID: "extnetidabc",
				},
			},
		},
	)

	err = dp.Ping(context.Background(), testPU1CtxID, pc)
	require.Nil(t, err)

	// NetSyn
	ipPacket, err := wrapIP(conn.data(), false, false, tcp.Syn)
	require.Nil(t, err)

	p, err := packet.New(packet.PacketTypeNetwork, ipPacket, "0", false)
	require.Nil(t, err)
	require.NotNil(t, p)
	payloadSize := len(p.ReadTCPData())
	tcpConn := connection.NewTCPConnection(puctx2, p)
	tcpConn.SourceController = srcCtrl
	pkt := &policy.FlowPolicy{Action: policy.Reject, PolicyID: "xyz"}

	ts := policy.NewTagStore()
	ts.AppendKeyValue(enforcerconstants.TransmitterLabel, testPU1CtxID)
	claims := &tokens.ConnectionClaims{
		P: pingPayload,
		T: ts,
	}

	pr := &collector.PingReport{
		PingID:               pc.ID,
		IterationID:          0,
		Type:                 gaia.PingProbeTypeRequest,
		PUID:                 testPU2CtxID,
		RemotePUID:           testPU1CtxID,
		Namespace:            testPU2NS,
		FourTuple:            "192.168.100.1:172.17.0.2:2020:80",
		RTT:                  "",
		Protocol:             6,
		ServiceType:          "L3",
		PayloadSize:          payloadSize,
		PayloadSizeType:      gaia.PingProbePayloadSizeTypeReceived,
		PolicyID:             "xyz",
		PolicyAction:         policy.Reject,
		AgentVersion:         "0.0.0",
		ApplicationListening: false,
		RemoteEndpointType:   collector.EndPointTypePU,
		SeqNum:               seqnum,
		TargetTCPNetworks:    true,
		ExcludedNetworks:     false,
		Claims:               []string{"a=b"},
		ClaimsType:           gaia.PingProbeClaimsTypeTransmitted,
		RemoteNamespace:      testPU1NSHash,
		RemoteNamespaceType:  gaia.PingProbeRemoteNamespaceTypeHash,
		ACLPolicyID:          "",
		ACLPolicyAction:      policy.ActionType(0),
		RemoteController:     srcCtrl,
		IsServer:             true,
		Error:                collector.PolicyDrop,
	}

	mockCollector.EXPECT().CollectPingEvent(pr).Times(1)
	copiedData, err := copystructure.Copy(pingPayload)
	synAckPayload := copiedData.(*policy.PingPayload)
	synAckPayload.NamespaceHash = testPU2NSHash
	require.Nil(t, err)
	mockTokenAccessor.EXPECT().CreateSynAckPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)

	oldsynAckDelay := synAckDelay
	synAckDelay = 1 * time.Second
	defer func() {
		synAckDelay = oldsynAckDelay
	}()

	err = dp.processPingNetSynPacket(puctx2, tcpConn, p, payloadSize, pkt, claims)
	require.Equal(t, errDropPingNetSyn, err)

	time.Sleep(2 * time.Second)

	// NetSynAck
	ipPacket, err = wrapIP(conn.data(), true, false, tcp.Syn|tcp.Ack)
	require.Nil(t, err)

	p, err = packet.New(packet.PacketTypeNetwork, ipPacket, "0", false)
	require.Nil(t, err)
	require.NotNil(t, p)

	item1, exists := dp.tcpClient.Get(p.L4ReverseFlowHash())
	if !exists {
		t.Fail()
	}
	tcpConn = item1
	tcpConn.DestinationController = dstCtrl

	pkt = &policy.FlowPolicy{Action: policy.Accept, PolicyID: "abc"}

	ts = policy.NewTagStore()
	ts.AppendKeyValue(enforcerconstants.TransmitterLabel, testPU2CtxID)
	claims = &tokens.ConnectionClaims{
		P: pingPayload,
		T: ts,
	}

	pr = &collector.PingReport{
		PingID:               pc.ID,
		IterationID:          0,
		Type:                 gaia.PingProbeTypeResponse,
		PUID:                 testPU1CtxID,
		RemotePUID:           testPU2CtxID,
		Namespace:            testPU1NS,
		FourTuple:            "172.17.0.2:192.168.100.1:80:2020",
		RTT:                  duration,
		Protocol:             6,
		ServiceType:          "L3",
		PayloadSize:          payloadSize,
		PayloadSizeType:      gaia.PingProbePayloadSizeTypeReceived,
		PolicyID:             "abc",
		PolicyAction:         policy.Accept,
		AgentVersion:         "0.0.0",
		ApplicationListening: false,
		RemoteEndpointType:   collector.EndPointTypePU,
		SeqNum:               seqnum,
		TargetTCPNetworks:    true,
		ExcludedNetworks:     false,
		Claims:               []string{"x=y"},
		ClaimsType:           gaia.PingProbeClaimsTypeTransmitted,
		RemoteNamespace:      testPU2NSHash,
		RemoteNamespaceType:  gaia.PingProbeRemoteNamespaceTypeHash,
		ACLPolicyID:          "extnetidabc",
		ACLPolicyAction:      policy.Accept,
		RemoteController:     dstCtrl,
	}

	mockCollector.EXPECT().CollectPingEvent(pr).Times(1)

	claims.P.NamespaceHash = testPU2NSHash
	err = dp.processPingNetSynAckPacket(puctx1, tcpConn, p, payloadSize, pkt, claims, false)
	require.Equal(t, errDropPingNetSynAck, err)
}

func Test_ValidPingUnequalSeqNum(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)
	mockTokenAccessor := mocktokenaccessor.NewMockTokenAccessor(ctrl)

	mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(3).Return([]byte("token"), nil).AnyTimes()
	mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(3).Return([]byte("token"), nil)

	dp, conn, err := setupDatapathAndPUs(ctrl, mockCollector, mockTokenAccessor)
	require.Nil(t, err)
	require.NotNil(t, dp)

	item, err := dp.puFromContextID.Get(testPU1CtxID)
	require.Nil(t, err)
	require.NotNil(t, item)
	puctx1 := item.(*pucontext.PUContext)

	item, err = dp.puFromContextID.Get(testPU2CtxID)
	require.Nil(t, err)
	require.NotNil(t, item)
	puctx2 := item.(*pucontext.PUContext)

	pc := &policy.PingConfig{
		ID:                "5e9e38ad39483e772044095e",
		IP:                dip,
		Port:              dpt,
		Iterations:        1,
		TargetTCPNetworks: true,
		ExcludedNetworks:  false,
	}

	pingPayload := &policy.PingPayload{
		PingID:               pc.ID,
		IterationID:          0,
		ApplicationListening: false,
		NamespaceHash:        testPU1NSHash,
	}

	err = dp.Ping(context.Background(), testPU1CtxID, pc)
	require.Nil(t, err)

	// NetSyn
	ipPacket, err := wrapIP(conn.data(), false, true, tcp.Syn)
	require.Nil(t, err)

	p, err := packet.New(packet.PacketTypeNetwork, ipPacket, "0", false)
	require.Nil(t, err)
	require.NotNil(t, p)
	payloadSize := len(p.ReadTCPData())
	tcpConn := connection.NewTCPConnection(puctx2, p)
	pkt := &policy.FlowPolicy{Action: policy.Accept, PolicyID: "abc"}

	ts := policy.NewTagStore()
	ts.AppendKeyValue(enforcerconstants.TransmitterLabel, testPU1CtxID)
	claims := &tokens.ConnectionClaims{
		P: pingPayload,
		T: ts,
	}

	pr := &collector.PingReport{
		PingID:               pc.ID,
		IterationID:          0,
		Type:                 gaia.PingProbeTypeRequest,
		PUID:                 testPU2CtxID,
		RemotePUID:           testPU1CtxID,
		Namespace:            testPU2NS,
		FourTuple:            "192.168.100.1:172.17.0.2:2020:80",
		RTT:                  "",
		Protocol:             6,
		ServiceType:          "L3",
		PayloadSize:          payloadSize,
		PayloadSizeType:      gaia.PingProbePayloadSizeTypeReceived,
		PolicyID:             "abc",
		PolicyAction:         policy.Accept,
		AgentVersion:         "0.0.0",
		ApplicationListening: false,
		RemoteEndpointType:   collector.EndPointTypePU,
		SeqNum:               111111,
		TargetTCPNetworks:    true,
		ExcludedNetworks:     false,
		Claims:               []string{"a=b"},
		ClaimsType:           gaia.PingProbeClaimsTypeTransmitted,
		RemoteNamespace:      testPU1NSHash,
		RemoteNamespaceType:  gaia.PingProbeRemoteNamespaceTypeHash,
		ACLPolicyID:          "",
		ACLPolicyAction:      policy.ActionType(0),
		IsServer:             true,
	}

	mockCollector.EXPECT().CollectPingEvent(pr).Times(1)
	copiedData, err := copystructure.Copy(pingPayload)
	synAckPayload := copiedData.(*policy.PingPayload)
	synAckPayload.NamespaceHash = testPU2NSHash
	require.Nil(t, err)
	mockTokenAccessor.EXPECT().CreateSynAckPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil)

	oldsynAckDelay := synAckDelay
	synAckDelay = 1 * time.Second
	defer func() {
		synAckDelay = oldsynAckDelay
	}()

	err = dp.processPingNetSynPacket(puctx2, tcpConn, p, payloadSize, pkt, claims)
	require.Equal(t, errDropPingNetSyn, err)

	time.Sleep(2 * time.Second)

	// NetSynAck
	ipPacket, err = wrapIP(conn.data(), true, false, tcp.Syn|tcp.Ack)
	require.Nil(t, err)

	p, err = packet.New(packet.PacketTypeNetwork, ipPacket, "0", false)
	require.Nil(t, err)
	require.NotNil(t, p)
	payloadSize = len(p.ReadTCPData())

	item1, _ := dp.tcpClient.Get(p.L4ReverseFlowHash())
	tcpConn = item1

	pkt = &policy.FlowPolicy{Action: policy.Reject, PolicyID: "cde"}

	ts = policy.NewTagStore()
	ts.AppendKeyValue(enforcerconstants.TransmitterLabel, testPU2CtxID)
	claims = &tokens.ConnectionClaims{
		P: pingPayload,
		T: ts,
	}

	pr = &collector.PingReport{
		PingID:               pc.ID,
		IterationID:          0,
		Type:                 gaia.PingProbeTypeResponse,
		PUID:                 testPU1CtxID,
		RemotePUID:           testPU2CtxID,
		Namespace:            testPU1NS,
		FourTuple:            "172.17.0.2:192.168.100.1:80:2020",
		RTT:                  duration,
		Protocol:             6,
		ServiceType:          "L3",
		PayloadSize:          payloadSize,
		PayloadSizeType:      gaia.PingProbePayloadSizeTypeReceived,
		PolicyID:             "cde",
		PolicyAction:         policy.Reject,
		AgentVersion:         "0.0.0",
		ApplicationListening: false,
		RemoteEndpointType:   collector.EndPointTypePU,
		SeqNum:               seqnum,
		TargetTCPNetworks:    true,
		ExcludedNetworks:     false,
		RemoteNamespace:      testPU2NSHash,
		RemoteNamespaceType:  gaia.PingProbeRemoteNamespaceTypeHash,
		Claims:               []string{"x=y"},
		ClaimsType:           gaia.PingProbeClaimsTypeTransmitted,
		ACLPolicyID:          "default",
		ACLPolicyAction:      policy.Reject | policy.Log,
		Error:                collector.PolicyDrop,
	}

	mockCollector.EXPECT().CollectPingEvent(pr).Times(1)
	claims.P.NamespaceHash = testPU2NSHash
	err = dp.processPingNetSynAckPacket(puctx1, tcpConn, p, payloadSize, pkt, claims, false)
	require.Equal(t, errDropPingNetSynAck, err)
}

func Test_ValidPingExtNet(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)
	mockTokenAccessor := mocktokenaccessor.NewMockTokenAccessor(ctrl)

	mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(3).Return([]byte("token"), nil).AnyTimes()
	mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(3).Return([]byte("token"), nil)

	dp, conn, err := setupDatapathAndPUs(ctrl, mockCollector, mockTokenAccessor)
	require.Nil(t, err)
	require.NotNil(t, dp)

	item, err := dp.puFromContextID.Get(testPU1CtxID)
	require.Nil(t, err)
	require.NotNil(t, item)
	puctx1 := item.(*pucontext.PUContext)

	pc := &policy.PingConfig{
		ID:                "5e9e38ad39483e772044095e",
		IP:                dip,
		Port:              dpt,
		Iterations:        1,
		TargetTCPNetworks: true,
		ExcludedNetworks:  false,
	}

	err = dp.Ping(context.Background(), testPU1CtxID, pc)
	require.Nil(t, err)

	// NetSynAck
	ipPacket, err := wrapIP(conn.data(), true, false, tcp.Syn)
	require.Nil(t, err)

	p, err := packet.New(packet.PacketTypeNetwork, ipPacket, "0", false)
	require.Nil(t, err)
	require.NotNil(t, p)
	payloadSize := len(p.ReadTCPData())

	item1, _ := dp.tcpClient.Get(p.L4ReverseFlowHash())
	tcpConn := item1

	pkt := &policy.FlowPolicy{Action: policy.Accept, PolicyID: "abc"}

	pr := &collector.PingReport{
		PingID:               pc.ID,
		IterationID:          0,
		Type:                 gaia.PingProbeTypeResponse,
		PUID:                 testPU1CtxID,
		Namespace:            testPU1NS,
		FourTuple:            "172.17.0.2:192.168.100.1:80:2020",
		RTT:                  duration,
		Protocol:             6,
		ServiceType:          "L3",
		PayloadSize:          payloadSize,
		PayloadSizeType:      gaia.PingProbePayloadSizeTypeReceived,
		PolicyID:             "abc",
		PolicyAction:         policy.Accept,
		AgentVersion:         "0.0.0",
		ApplicationListening: true,
		RemoteNamespaceType:  gaia.PingProbeRemoteNamespaceTypeHash,
		RemoteEndpointType:   collector.EndPointTypeExternalIP,
		SeqNum:               seqnum,
		TargetTCPNetworks:    true,
		ExcludedNetworks:     false,
		Claims:               []string{"x=y"},
		ClaimsType:           gaia.PingProbeClaimsTypeTransmitted,
		ACLPolicyID:          "default",
		ACLPolicyAction:      policy.Reject | policy.Log,
	}

	mockCollector.EXPECT().CollectPingEvent(pr).Times(1)

	// NOTE: Overriding the default conn timeout of 15s to 3s.
	oldremoveDelay := removeDelay
	removeDelay = 2 * time.Second
	defer func() {
		removeDelay = oldremoveDelay
	}()

	tcpConn.ChangeConnectionTimeout(3 * time.Second)
	err = dp.processPingNetSynAckPacket(puctx1, tcpConn, p, payloadSize, pkt, nil, true)
	require.Equal(t, errDropPingNetSynAck, err)

	require.Equal(t, connection.TCPSynAckReceived, tcpConn.GetState())

	time.Sleep(4 * time.Second)

	_, exists := dp.tcpClient.Get(p.L4ReverseFlowHash())
	if exists {
		t.Fail()
	}
}

func Test_PingRequestTimeout(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCollector := mockcollector.NewMockEventCollector(ctrl)
	mockTokenAccessor := mocktokenaccessor.NewMockTokenAccessor(ctrl)

	mockTokenAccessor.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(3).Return([]byte("token"), nil).AnyTimes()
	mockTokenAccessor.EXPECT().CreateSynPacketToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(3).Return([]byte("token"), nil)

	dp, _, err := setupDatapathAndPUs(ctrl, mockCollector, mockTokenAccessor)
	require.Nil(t, err)
	require.NotNil(t, dp)

	pc := &policy.PingConfig{
		ID:                "5e9e38ad39483e772044095e",
		IP:                dip,
		Port:              dpt,
		Iterations:        1,
		TargetTCPNetworks: true,
		ExcludedNetworks:  true,
	}

	pr := &collector.PingReport{
		PingID:               pc.ID,
		IterationID:          0,
		Type:                 gaia.PingProbeTypeRequest,
		PUID:                 testPU1CtxID,
		Namespace:            testPU1NS,
		FourTuple:            "192.168.100.1:172.17.0.2:2020:80",
		RTT:                  "",
		Protocol:             6,
		ServiceType:          "L3",
		PayloadSize:          5,
		PayloadSizeType:      gaia.PingProbePayloadSizeTypeTransmitted,
		PolicyID:             "",
		PolicyAction:         policy.ActionType(0), // Not a valid action, defaults to "unknown"
		AgentVersion:         "0.0.0",
		ApplicationListening: false,
		SeqNum:               seqnum,
		RemoteNamespaceType:  gaia.PingProbeRemoteNamespaceTypeHash,
		TargetTCPNetworks:    true,
		ExcludedNetworks:     true,
		Claims:               []string{"x=y"},
		ClaimsType:           gaia.PingProbeClaimsTypeTransmitted,
		ACLPolicyID:          "default",
		ACLPolicyAction:      policy.Reject | policy.Log,
		Error:                policy.ErrExcludedNetworks,
	}

	mockCollector.EXPECT().CollectPingEvent(pr).Times(1)

	oldconnTimeout := connection.DefaultConnectionTimeout
	connection.DefaultConnectionTimeout = 3 * time.Second
	defer func() {
		connection.DefaultConnectionTimeout = oldconnTimeout
	}()

	err = dp.Ping(context.Background(), testPU1CtxID, pc)
	require.Nil(t, err)
	time.Sleep(4 * time.Second)

	list := dp.tcpClient.Len()
	if list != 0 {
		t.Fail()
	}
}
